"""封存已确认的来源和记录版本，不替外部协议判断完整性。

扩展部分为联邦采集的原始收据与归并结果：
- receipts：每个实例每个请求地址的原始字节、请求/最终地址、验证结果；
- instances：来源实例的可达状态，失联只是失联，不产生删除结论；
- activities / snapshots：按活动 ID 与对象 ID 分列的解析结果；
- objects / object_evidence / pending_refs：归并投影的可核验依据
  与悬而未决的引用。

所有写入在同一事务内完成；已存在但内容不同的收据按版本冲突处理，
保持“冲突事务不留下半成品”的旧有约定。
"""
import hashlib,json,sqlite3
from .io import asset
from .adapter import decode

SCHEMA = (
"CREATE TABLE IF NOT EXISTS sources(collection TEXT,digest TEXT,raw BLOB,PRIMARY KEY(collection,digest));"
"CREATE TABLE IF NOT EXISTS records(collection TEXT,kind TEXT,record_id TEXT,version TEXT,source_digest TEXT,refs TEXT,payload TEXT,PRIMARY KEY(collection,kind,record_id,version),FOREIGN KEY(collection,source_digest) REFERENCES sources(collection,digest));"
# ---- 联邦采集扩展 ----
"CREATE TABLE IF NOT EXISTS receipts(collection TEXT,receipt_id TEXT,endpoint_role TEXT,requested_url TEXT,final_url TEXT,origin TEXT,status INTEGER,error TEXT,body BLOB,headers TEXT,hops TEXT,digest_ok INTEGER,signature_ok INTEGER,verification TEXT,received_order INTEGER,PRIMARY KEY(collection,receipt_id));"
"CREATE TABLE IF NOT EXISTS instances(collection TEXT,origin TEXT,reachable INTEGER,last_status INTEGER,last_error TEXT,checked_receipt_id TEXT,PRIMARY KEY(collection,origin));"
"CREATE TABLE IF NOT EXISTS activities(collection TEXT,activity_id TEXT,activity_type TEXT,actor TEXT,object_id TEXT,published TEXT,receipt_id TEXT,stream_order INTEGER,actor_verified INTEGER,verification_detail TEXT,payload TEXT,PRIMARY KEY(collection,activity_id));"
"CREATE TABLE IF NOT EXISTS snapshots(collection TEXT,object_id TEXT,object_type TEXT,content TEXT,actor TEXT,receipt_id TEXT,stream_order INTEGER,actor_verified INTEGER,PRIMARY KEY(collection,object_id,receipt_id));"
"CREATE TABLE IF NOT EXISTS objects(collection TEXT,object_id TEXT,state TEXT,summary TEXT,updated_by_activity TEXT,decision TEXT,decision_reasons TEXT,PRIMARY KEY(collection,object_id));"
"CREATE TABLE IF NOT EXISTS object_evidence(collection TEXT,object_id TEXT,activity_id TEXT,activity_type TEXT,actor TEXT,receipt_id TEXT,effect TEXT,PRIMARY KEY(collection,object_id,activity_id));"
"CREATE TABLE IF NOT EXISTS pending_refs(collection TEXT,object_id TEXT,referenced_by_activity TEXT,origin TEXT,resolved INTEGER,note TEXT,PRIMARY KEY(collection,object_id,referenced_by_activity));"
)

def connect(path):
 c=sqlite3.connect(path);c.execute('PRAGMA foreign_keys=ON');c.executescript(SCHEMA);return c
def receive(c,manifest,root):
 raw=asset(root,manifest['assets'][0]);digest=hashlib.sha256(raw).hexdigest();doc=decode(raw,manifest) if manifest['assets'][0]['path'] in ('protocol-source.bin','conflict-source.bin') else json.loads(raw.decode('utf-8'))
 if doc.get('collection')!=manifest['collection'] or doc.get('protocol')!=manifest['protocol']:raise ValueError('来源身份不匹配')
 with c:
  c.execute('INSERT OR IGNORE INTO sources VALUES(?,?,?)',(doc['collection'],digest,raw))
  for row in doc['records']:
   refs=json.dumps(row.get('refs',[]),ensure_ascii=False);payload=json.dumps(row['payload'],ensure_ascii=False,sort_keys=True)
   old=c.execute('SELECT source_digest,payload FROM records WHERE collection=? AND kind=? AND record_id=? AND version=?',(doc['collection'],row['kind'],row['id'],row['version'])).fetchone()
   if old and old!=(digest,payload):raise ValueError('版本冲突')
   c.execute('INSERT OR IGNORE INTO records VALUES(?,?,?,?,?,?,?)',(doc['collection'],row['kind'],row['id'],row['version'],digest,refs,payload))
 return digest

# ---------------- 联邦采集写入助手 ----------------

def _conflict(c, table, identity, existing, incoming):
    if existing != incoming:
        raise ValueError('版本冲突: %s %s' % (table, identity))

def upsert_receipt(c, collection, r):
    """写入或幂等更新原始收据；同 ID 不同内容即冲突。"""
    old = c.execute(
        'SELECT origin,status,error,body,headers,hops,digest_ok,signature_ok,verification,endpoint_role,final_url '
        'FROM receipts WHERE collection=? AND receipt_id=?',
        (collection, r['receipt_id'])).fetchone()
    incoming = (r['origin'], r['status'], r['error'], r['body'],
                r['headers_json'], r['hops_json'], int(r['digest_ok']),
                int(r['signature_ok']), r['verification_json'],
                r['endpoint_role'], r['final_url'])
    if old is not None:
        _conflict(c, 'receipts', r['receipt_id'], old, incoming)
        return
    c.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
        collection, r['receipt_id'], r['endpoint_role'], r['requested_url'],
        r['final_url'], r['origin'], r['status'], r['error'], r['body'],
        r['headers_json'], r['hops_json'], int(r['digest_ok']),
        int(r['signature_ok']), r['verification_json'], r['received_order']))

def upsert_instance(c, collection, origin, reachable, status, error, receipt_id):
    """实例表记录最近一次探测：同实例的新收据覆盖旧状态而非冲突。

    失联历史仍可从 receipts 表逐次追溯，这里只回答“最近是否可达”。
    """
    c.execute('INSERT INTO instances VALUES(?,?,?,?,?,?) '
              'ON CONFLICT(collection,origin) DO UPDATE SET '
              'reachable=excluded.reachable,last_status=excluded.last_status,'
              'last_error=excluded.last_error,'
              'checked_receipt_id=excluded.checked_receipt_id',
              (collection, origin, int(reachable), status, error, receipt_id))

def upsert_activity(c, collection, a):
    old = c.execute(
        'SELECT activity_type,actor,object_id,published,receipt_id,stream_order,actor_verified,verification_detail,payload '
        'FROM activities WHERE collection=? AND activity_id=?',
        (collection, a['activity_id'])).fetchone()
    incoming = (a['activity_type'], a['actor'], a['object_id'], a['published'],
                a['receipt_id'], a['stream_order'], int(a['actor_verified']),
                a['verification_detail'], a['payload_json'])
    if old is not None:
        _conflict(c, 'activities', a['activity_id'], old, incoming)
        return
    c.execute('INSERT INTO activities VALUES(?,?,?,?,?,?,?,?,?,?,?)', (
        collection, a['activity_id'], a['activity_type'], a['actor'],
        a['object_id'], a['published'], a['receipt_id'], a['stream_order'],
        int(a['actor_verified']), a['verification_detail'], a['payload_json']))

def add_snapshot(c, collection, s):
    old = c.execute(
        'SELECT 1 FROM snapshots WHERE collection=? AND object_id=? AND receipt_id=?',
        (collection, s['object_id'], s['receipt_id'])).fetchone()
    if old is not None:
        return
    c.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?)', (
        collection, s['object_id'], s['object_type'], s['content'],
        s['actor'], s['receipt_id'], s['stream_order'],
        int(s['actor_verified'])))

def replace_derived(c, collection, objects, evidence, pending):
    """归并结果整体替换：投影永远由已封存收据重新推导，无历史半成品。"""
    c.execute('DELETE FROM objects WHERE collection=?', (collection,))
    c.execute('DELETE FROM object_evidence WHERE collection=?', (collection,))
    c.execute('DELETE FROM pending_refs WHERE collection=?', (collection,))
    for o in objects:
        c.execute('INSERT INTO objects VALUES(?,?,?,?,?,?,?)', (
            collection, o['object_id'], o['state'], o['summary'],
            o['updated_by_activity'], o['decision'],
            json.dumps(o['decision_reasons'], ensure_ascii=False)))
    for e in evidence:
        c.execute('INSERT INTO object_evidence VALUES(?,?,?,?,?,?,?)', (
            collection, e['object_id'], e['activity_id'], e['activity_type'],
            e['actor'], e['receipt_id'], e['effect']))
    for p in pending:
        c.execute('INSERT INTO pending_refs VALUES(?,?,?,?,?,?)', (
            collection, p['object_id'], p['referenced_by_activity'],
            p['origin'], int(p['resolved']), p['note']))
