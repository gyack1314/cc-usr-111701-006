"""联邦采集、核验与因果归并。

身份约定（四者分列，严禁混用）：
- activity_id：活动自身的全局 ID；
- object_id：活动所指对象的全局 ID，跨实例 Announce 指向同一 object_id
  时在档案中归并为同一对象，转发本身各留各的收据；
- actor：活动发送者；
- requested_url / final_url / origin：我们请求的地址、最终响应地址与
  实际应答来源实例。

规则：
- 只有摘要与签名都通过、且签名密钥来源与 actor 同源的活动才算作者已核验；
- Update/Delete 必须由对象作者发出，并按 published（缺失时按接收序）
  排序形成因果顺序；墓碑之后的修订与撤回记入拒绝原因；
- Announce/Undo 属于转发证据，任何已核验发送者都可提交，永久保留，
  Undo 只撤回转发效果，不删除证据行；
- 实例失联只登记 unreachable，绝不据此把对象转为墓碑；
- 迟到的跨实例引用先入 pending_refs，后续收据可将其闭合。
"""
import hashlib
import json

from .transport import fetch, origin_of, redacted_headers
from .verification import verify_receipt

ACTIVITY_TYPES = ('Create', 'Update', 'Delete', 'Announce', 'Undo')
LIFECYCLE_TYPES = ('Create', 'Update', 'Delete')
FORWARD_TYPES = ('Announce', 'Undo')


def _json_loads(raw):
    return json.loads(
        raw.decode('utf-8'),
        parse_constant=lambda x: (_ for _ in ()).throw(
            ValueError('非有限JSON常量')))


def parse_inbox(doc):
    """解析 ActivityStreams 集合文档为规范化活动列表。"""
    if not isinstance(doc, dict):
        raise ValueError('收件箱文档必须为对象')
    items = doc.get('orderedItems')
    if not isinstance(items, list):
        raise ValueError('缺少 orderedItems')
    out = []
    for pos, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError('活动必须为对象')
        atype = item.get('type')
        if atype not in ACTIVITY_TYPES:
            raise ValueError('活动类型非法: %r' % atype)
        actor = item.get('actor')
        if not actor:
            raise ValueError('活动缺少 actor')
        obj = item.get('object')
        if isinstance(obj, dict):
            object_id = obj.get('id')
            embedded = obj
        else:
            object_id, embedded = obj, None
        if not object_id:
            raise ValueError('活动缺少对象 ID')
        undo_target = None
        if atype == 'Undo' and isinstance(obj, dict):
            undo_target = obj.get('id')
        out.append({
            'activity_id': item['id'],
            'activity_type': atype,
            'actor': actor,
            'object_id': object_id,
            'embedded': embedded,
            'undo_target': undo_target,
            'published': item.get('published'),
            'position': pos,
        })
    # Undo 内嵌的是被撤回的活动（Announce/Delete），其归并对象应解析为
    # 目标活动所作用的对象；活动 ID 与对象 ID 在此显式分列。
    by_id = {x['activity_id']: x for x in out}
    for item in out:
        if item['activity_type'] == 'Undo' and item['undo_target']:
            target = by_id.get(item['undo_target'])
            if target is not None:
                item['object_id'] = target['object_id']
    return out


def parse_object_doc(doc):
    """解析对象地址返回的对象文档（Note 等）。"""
    if not isinstance(doc, dict) or not doc.get('id'):
        raise ValueError('对象文档缺少 id')
    return {
        'object_id': doc['id'],
        'object_type': doc.get('type'),
        'content': doc.get('content'),
        'actor': doc.get('attributedTo'),
    }


def _origin_or_none(url):
    try:
        return origin_of(url)
    except (ValueError, AttributeError):
        return None


class Collector:
    """按抓取计划从授权端点采集，冻结收据并触发归并。"""

    def __init__(self, transport, verifier, auth_headers=None):
        self.transport = transport
        self.verifier = verifier
        self.auth_headers = dict(auth_headers or {})

    @staticmethod
    def _stream_for(receipt_order, position):
        # 收据序号 * 1000 + 集合内位置：跨重跑稳定，支持迟到端点
        return receipt_order * 1000 + position

    def collect(self, c, collection, plan):
        endpoints = plan.get('endpoints')
        if not isinstance(endpoints, list) or not endpoints:
            raise ValueError('抓取计划缺少 endpoints')
        with c:
            # 重跑同一计划时复用既有收据身份与序号，保证幂等；
            # 计划中新增的端点才分配新序号（支持迟到的跨实例引用）。
            prior = {row[0]: (row[1], row[2]) for row in c.execute(
                'SELECT requested_url,receipt_id,received_order '
                'FROM receipts WHERE collection=?', (collection,))}
            state = {'max_order': max((v[1] for v in prior.values()),
                                      default=0)}
            for ep in endpoints:
                self._collect_endpoint(
                    c, collection, ep, prior, state)
            self.reduce(c, collection)

    def _collect_endpoint(self, c, collection, ep, prior, state):
        from . import journal
        role = ep['role']
        if role not in ('inbox', 'object'):
            raise ValueError('端点角色非法: %r' % role)
        url = ep['url']
        headers = dict(self.auth_headers)
        headers.update(ep.get('headers') or {})
        headers.setdefault('Accept',
                           'application/activity+json, application/ld+json')
        result = fetch(self.transport, url, headers)
        if url in prior:
            receipt_id, order = prior[url]
        else:
            state['max_order'] += 1
            order = state['max_order']
            receipt_id = 'receipt-%d-%s' % (
                order, hashlib.sha256(url.encode('utf-8')).hexdigest()[:12])
        if result.ok:
            verification = verify_receipt(
                'GET', result.final_url, result.headers,
                result.body, self.verifier)
            v_json = json.dumps(verification.__dict__, ensure_ascii=False)
            final_origin = origin_of(result.final_url)
        else:
            verification = None
            v_json = json.dumps({'verified': False,
                                 'detail': result.error or '抓取失败'},
                                ensure_ascii=False)
            final_origin = _origin_or_none(result.final_url or url)
        journal.upsert_receipt(c, collection, {
            'receipt_id': receipt_id,
            'endpoint_role': role,
            'requested_url': url,
            'final_url': result.final_url,
            'origin': final_origin,
            'status': result.status,
            'error': result.error,
            'body': result.body,
            'headers_json': json.dumps(
                redacted_headers(result.headers), ensure_ascii=False),
            'hops_json': json.dumps(
                [h.__dict__ for h in result.hops], ensure_ascii=False),
            'digest_ok': bool(verification and verification.digest_ok),
            'signature_ok': bool(verification and verification.signature_ok),
            'verification_json': v_json,
            'received_order': order,
        })
        journal.upsert_instance(
            c, collection, final_origin or _origin_or_none(url),
            reachable=result.ok, status=result.status,
            error=result.error, receipt_id=receipt_id)
        if not result.ok:
            # 缺席不是删除：不产生任何对象状态，只留下失联记录
            return
        if role == 'inbox':
            doc = _json_loads(result.body)
            for item in parse_inbox(doc):
                self._store_activity(
                    c, collection, item, receipt_id, final_origin,
                    verification, self._stream_for(order, item['position']))
        else:
            doc = _json_loads(result.body)
            snap = parse_object_doc(doc)
            actor_verified, detail = self._actor_check(
                snap['actor'], final_origin, verification)
            journal.add_snapshot(c, collection, {
                'object_id': snap['object_id'],
                'object_type': snap['object_type'],
                'content': snap['content'],
                'actor': snap['actor'],
                'receipt_id': receipt_id,
                'stream_order': self._stream_for(order, 500),
                'actor_verified': actor_verified,
            })
            if not actor_verified:
                # 未核验快照不入证据；原因在归并阶段进入 decision_reasons
                pass

    def _actor_check(self, actor, receipt_origin, verification):
        """发送者核验：收据已核验且签名密钥来源与 actor 同源。

        应答实例与 actor 不同源时（如对象地址 302 到镜像 CDN，但响应
        仍由作者密钥签名），作者身份依然成立；镜像事实在 detail 中标注，
        最终地址与来源实例仍分别留存在收据里。
        """
        if verification is None or not verification.verified:
            return False, '收据未完成核验'
        if not actor:
            return False, '缺少 actor/attributedTo'
        actor_origin = _origin_or_none(actor)
        if actor_origin is None:
            return False, 'actor 地址无法解析来源'
        if verification.signed_by_origin != actor_origin:
            return False, '签名来源 %s 与 actor 来源 %s 不一致' % (
                verification.signed_by_origin, actor_origin)
        if receipt_origin != actor_origin:
            return True, '作者已核验（镜像应答: %s）' % receipt_origin
        return True, '作者已核验'

    def _store_activity(self, c, collection, item, receipt_id,
                        receipt_origin, verification, stream_order):
        from . import journal
        actor_verified, detail = self._actor_check(
            item['actor'], receipt_origin, verification)
        journal.upsert_activity(c, collection, {
            'activity_id': item['activity_id'],
            'activity_type': item['activity_type'],
            'actor': item['actor'],
            'object_id': item['object_id'],
            'published': item['published'],
            'receipt_id': receipt_id,
            'stream_order': stream_order,
            'actor_verified': actor_verified,
            'verification_detail': detail,
            'payload_json': json.dumps(
                {k: v for k, v in item.items() if k != 'embedded'},
                ensure_ascii=False, sort_keys=True),
        })

    # ---------------- 因果归并（可从已封存数据重复推导） ----------------

    def reduce(self, c, collection):
        from . import journal
        activities = c.execute(
            'SELECT activity_id,activity_type,actor,object_id,published,'
            'receipt_id,stream_order,actor_verified,verification_detail,payload '
            'FROM activities WHERE collection=?', (collection,)).fetchall()
        snapshots = c.execute(
            'SELECT object_id,object_type,content,actor,receipt_id,'
            'stream_order,actor_verified FROM snapshots '
            'WHERE collection=? ORDER BY stream_order', (collection,)).fetchall()

        objects = {}
        evidence = []
        author = {}
        latest_content = {}

        def ensure(oid):
            if oid not in objects:
                objects[oid] = {
                    'object_id': oid, 'state': 'pending',
                    'summary': None, 'updated_by_activity': None,
                    'decision': 'incomplete', 'decision_reasons': []}
            return objects[oid]

        def reasons(oid):
            return ensure(oid)['decision_reasons']

        # 已核验快照直接建立对象内容；未核验快照只留原因
        for oid, otype, content, sactor, rid, sorder, sv in snapshots:
            obj = ensure(oid)
            if sv:
                author.setdefault(oid, sactor)
                latest_content[oid] = {'type': otype, 'content': content,
                                       'receipt_id': rid}
                if obj['state'] == 'pending':
                    obj['state'] = 'active'
                    obj['summary'] = content
                evidence.append({
                    'object_id': oid, 'activity_id': None,
                    'activity_type': 'Snapshot', 'actor': sactor,
                    'receipt_id': rid, 'effect': 'verified-snapshot'})
            else:
                reasons(oid).append(
                    '对象地址快照未通过作者核验: %s' % rid)

        verified = [a for a in activities if a[7]]
        unverified = [a for a in activities if not a[7]]

        def order_key(a):
            return (a[4] or '', a[6])

        lifecycle = sorted(
            (a for a in verified if a[1] in LIFECYCLE_TYPES),
            key=order_key)
        forwards = sorted(
            (a for a in verified if a[1] in FORWARD_TYPES),
            key=order_key)

        for a in lifecycle:
            aid, atype, actor_id, oid = a[0], a[1], a[2], a[3]
            rid = a[5]
            obj = ensure(oid)
            if atype == 'Create':
                if author.setdefault(oid, actor_id) != actor_id:
                    reasons(oid).append(
                        'Create %s 的发送者 %s 不是已确立作者 %s，已拒绝'
                        % (aid, actor_id, author[oid]))
                    continue
                if obj['state'] == 'pending':
                    obj['state'] = 'active'
                evidence.append({
                    'object_id': oid, 'activity_id': aid,
                    'activity_type': atype, 'actor': actor_id,
                    'receipt_id': rid, 'effect': 'created'})
            elif atype == 'Update':
                if oid not in author:
                    reasons(oid).append(
                        'Update %s 到达时对象尚无已核验 Create，悬挂等待'
                        % aid)
                elif actor_id != author[oid]:
                    reasons(oid).append(
                        'Update %s 的发送者 %s 非作者 %s，已拒绝'
                        % (aid, actor_id, author[oid]))
                elif obj['state'] == 'tombstone':
                    reasons(oid).append(
                        'Update %s 晚于墓碑，因果顺序上不生效' % aid)
                else:
                    obj['state'] = 'updated'
                    obj['updated_by_activity'] = aid
                    evidence.append({
                        'object_id': oid, 'activity_id': aid,
                        'activity_type': atype, 'actor': actor_id,
                        'receipt_id': rid, 'effect': 'updated'})
            else:  # Delete
                if oid not in author:
                    reasons(oid).append(
                        'Delete %s 到达时对象尚无已核验 Create，悬挂等待'
                        % aid)
                elif actor_id != author[oid]:
                    reasons(oid).append(
                        'Delete %s 的发送者 %s 非作者 %s，已拒绝'
                        % (aid, actor_id, author[oid]))
                elif obj['state'] == 'tombstone':
                    reasons(oid).append(
                        'Delete %s 重复作用于墓碑，忽略' % aid)
                else:
                    obj['state'] = 'tombstone'
                    evidence.append({
                        'object_id': oid, 'activity_id': aid,
                        'activity_type': atype, 'actor': actor_id,
                        'receipt_id': rid, 'effect': 'deleted'})

        # 转发证据：Announce 永久留存；Undo 撤回转发效果或恢复墓碑
        announce_index = {e['activity_id']: e for e in evidence
                          if e['activity_type'] == 'Announce'}
        for a in forwards:
            aid, atype, actor_id, oid = a[0], a[1], a[2], a[3]
            rid = a[5]
            obj = ensure(oid)
            if atype == 'Announce':
                row = {
                    'object_id': oid, 'activity_id': aid,
                    'activity_type': atype, 'actor': actor_id,
                    'receipt_id': rid, 'effect': 'forwarded'}
                evidence.append(row)
                announce_index[aid] = row
                continue
            target = self._undo_target(activities, aid)
            matched = announce_index.get(target)
            if matched is not None:
                matched['effect'] = 'forwarded-then-withdrawn'
                evidence.append({
                    'object_id': oid, 'activity_id': aid,
                    'activity_type': 'Undo', 'actor': actor_id,
                    'receipt_id': rid,
                    'effect': 'withdrew:%s' % target})
                continue
            restored, note = self._apply_undo_delete(
                obj, target, activities, aid, actor_id, rid)
            if note:
                reasons(oid).append(note)
            if restored:
                evidence.append({
                    'object_id': oid, 'activity_id': aid,
                    'activity_type': 'Undo', 'actor': actor_id,
                    'receipt_id': rid,
                    'effect': 'restored:%s' % target})

        # 未核验活动只产生拒绝原因，绝不改变状态
        for a in unverified:
            aid, atype, actor_id, oid = a[0], a[1], a[2], a[3]
            ensure(oid)
            reasons(oid).append(
                '%s %s 作者未核验（%s），不参与状态归并'
                % (atype, aid, a[8]))

        # 悬而未决的引用：被引用但没有已核验生命周期活动或快照的对象
        established = {oid for oid, obj in objects.items()
                       if obj['state'] != 'pending'}
        pending = []
        for a in activities:
            aid, oid = a[0], a[3]
            resolved = oid in established
            pending.append({
                'object_id': oid,
                'referenced_by_activity': aid,
                'origin': _origin_or_none(oid),
                'resolved': resolved,
                'note': '' if resolved else '引用对象尚未取得已核验原文',
            })

        for oid, obj in objects.items():
            if obj['state'] != 'pending':
                obj['decision'] = 'verified-state'
                snap = latest_content.get(oid)
                if snap and obj['state'] in ('active', 'updated'):
                    obj['summary'] = snap['content']
            else:
                obj['decision'] = 'incomplete'
        # 仅被转发、从未取得作者原文的对象也进入对象集（保持 pending）
        for p in pending:
            if not p['resolved']:
                ensure(p['object_id'])

        journal.replace_derived(
            c, collection,
            sorted(objects.values(), key=lambda o: o['object_id']),
            evidence, pending)

    @staticmethod
    def _undo_target(activities, undo_id):
        row = next((a for a in activities if a[0] == undo_id), None)
        if row is None:
            return None
        payload = json.loads(row[9])
        return payload.get('undo_target') or payload.get('object_id')

    @staticmethod
    def _apply_undo_delete(obj, target, activities, aid, actor_id, rid):
        target_row = next((a for a in activities if a[0] == target), None)
        if target_row is None or target_row[1] != 'Delete':
            return False, 'Undo %s 的目标 %s 无对应已核验 Delete，悬挂' % (
                aid, target)
        if target_row[2] != actor_id:
            return False, 'Undo %s 的发送者与原 Delete 作者不一致，已拒绝' % aid
        if obj['state'] != 'tombstone':
            return False, 'Undo %s 目标 Delete 生效时对象并非墓碑，忽略' % aid
        obj['state'] = 'active'
        return True, None
