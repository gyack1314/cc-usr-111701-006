"""联邦采集端到端规则核验。

覆盖：
- 异源重定向剥离认证、请求地址与最终响应地址分列；
- 实例失联不产生删除结论；
- 跨实例 Announce 归并为同一对象且转发证据永久保留；
- 仅已核验作者的 Update/Delete 按因果顺序生效，伪造/越权被拒绝；
- Undo(Delete) 恢复对象、Undo(Announce) 只撤回转发效果；
- 悬而未决引用可被迟到收据闭合；
- 重跑同一计划幂等；显示状态可追溯到具体已核验活动。
"""
import json
import tempfile
import unittest
from pathlib import Path

from capture_data.federation import Collector
from capture_data.federation_view import federation_overview
from capture_data.journal import connect
from capture_data.transport import (
    ReplayTransport, fetch, origin_of, redacted_headers)
from capture_data.verification import HmacVerifier

DATA = Path(__file__).resolve().parents[1] / 'data'
SOCIAL = 'https://social.example.test'
FRIEND_A = 'https://friend-a.example.test'
FRIEND_B = 'https://friend-b.example.test'
CDN = 'https://cdn-archive.example.net'
MEI = SOCIAL + '/users/mei'
LI = FRIEND_A + '/users/li'
WANG = FRIEND_B + '/users/wang'
OBJ19 = SOCIAL + '/objects/19'
OBJ20 = SOCIAL + '/objects/20'


def load_plan():
    plan = json.loads((DATA / 'federation-plan.json').read_bytes())
    replay = json.loads((DATA / 'federation-replay.bin').read_bytes())
    return plan, replay


def run_collect(plan, replay, auth=True, db_path=':memory:'):
    c = connect(db_path)
    transport = ReplayTransport(replay['rows'])
    verifier = HmacVerifier(plan['keys'])
    headers = {'Authorization': 'Bearer archive-token',
               'Cookie': 'session=abc'} if auth else {}
    Collector(transport, verifier, headers).collect(
        c, plan['collection'], plan)
    return c, transport


class FederationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.replay = load_plan()
        cls.db, cls.transport = run_collect(cls.plan, cls.replay)
        cls.view = federation_overview(cls.db, cls.plan['collection'])

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_receipts_keep_originals_and_separate_urls(self):
        receipts = self.view['receipts']
        # 5 个端点中对象地址产生两跳，共 6 条请求收据（含 1 条错误）
        self.assertEqual(self.view['counts']['receipts'], 6)
        obj_receipt = next(r for r in receipts
                           if r['requested_url'] == SOCIAL + '/objects/19')
        # 请求地址与实际响应地址分列
        self.assertEqual(obj_receipt['requested_url'], SOCIAL + '/objects/19')
        self.assertEqual(obj_receipt['final_url'], CDN + '/mirror/19')
        self.assertNotEqual(origin_of(obj_receipt['requested_url']),
                            obj_receipt['origin'])
        # 原文与验证结果都留存在收据里
        self.assertTrue(obj_receipt['digest_ok'])
        self.assertTrue(obj_receipt['signature_ok'])
        self.assertGreater(obj_receipt['body_bytes'], 0)
        self.assertEqual(len(obj_receipt['hops']), 1)

    def test_02_redirect_strips_credentials_cross_origin(self):
        # 重放器在异源跳变时断言 authorization/cookie 不存在
        requests = self.transport.requests
        cdn = next(q for q in requests if q['url'] == CDN + '/mirror/19')
        self.assertNotIn('authorization',
                         {k.lower() for k in cdn['headers']})
        self.assertNotIn('cookie', {k.lower() for k in cdn['headers']})
        # 同源首跳仍携带认证
        first = next(q for q in requests
                     if q['url'] == SOCIAL + '/objects/19')
        self.assertIn('authorization',
                      {k.lower() for k in first['headers']})
        # 记录请求头时敏感值已隐去
        self.assertTrue(all(v == '<redacted>'
                            for k, v in first['headers'].items()
                            if k.lower() in ('authorization', 'cookie')))

    def test_03_unreachable_instance_is_not_a_delete(self):
        unreachable = self.view['unreachable_instances']
        self.assertEqual(len(unreachable), 1)
        self.assertEqual(unreachable[0]['origin'],
                         origin_of('https://down.example.test/inbox'))
        self.assertFalse(unreachable[0]['reachable'])
        self.assertIsNotNone(unreachable[0]['last_error'])
        # 没有任何对象因为该实例失联进入墓碑
        self.assertNotIn('https://down.example.test/',
                         [o['object_id'] for o in self.view['objects']])

    def test_04_announces_merge_to_one_object_with_evidence(self):
        obj = next(o for o in self.view['objects']
                   if o['object_id'] == OBJ19)
        # 两个实例的转发 + 作者生命周期活动归并为同一对象
        forwards = [e for e in obj['verified_basis']
                    if e['activity_type'] == 'Announce']
        actors = {e['actor'] for e in forwards}
        self.assertEqual(actors, {LI, WANG})
        # 转发证据永久保留，即便其中一条后来被 Undo
        effects = {e['activity_id']: e['effect']
                   for e in obj['verified_basis']}
        self.assertIn(FRIEND_B + '/activities/b1', effects)

    def test_05_identities_are_separate_columns(self):
        rows = self.db.execute(
            'SELECT activity_id,activity_type,actor,object_id,receipt_id '
            "FROM activities WHERE activity_id=?",
            (SOCIAL + '/activities/u1',)).fetchall()
        self.assertEqual(len(rows), 1)
        aid, atype, actor, oid, rid = rows[0]
        # 活动 ID、对象 ID、发送者是三个不同命名空间的标识
        self.assertEqual(aid, SOCIAL + '/activities/u1')
        self.assertEqual(oid, OBJ19)
        self.assertEqual(actor, MEI)
        self.assertEqual(len({aid, oid, actor}), 3)
        receipt = self.db.execute(
            'SELECT requested_url,final_url,origin FROM receipts '
            'WHERE receipt_id=?', (rid,)).fetchone()
        # 响应地址独立成列，不回写到活动 ID / 对象 ID / actor 任一字段
        self.assertNotIn(receipt[0], (aid, oid, actor))
        self.assertNotIn(receipt[1], (aid, oid, actor))
        self.assertEqual(receipt[2], origin_of(receipt[0]))
        # 对象表以 object_id 为主键，活动表以 activity_id 为主键，互不覆盖
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM objects WHERE object_id=?', (oid,)).fetchone()[0], 1)
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM activities WHERE activity_id=?', (aid,)).fetchone()[0], 1)

    def test_06_author_only_update_delete_in_causal_order(self):
        obj = next(o for o in self.view['objects']
                   if o['object_id'] == OBJ19)
        effects = {e['activity_id']: e['effect']
                   for e in obj['verified_basis']}
        self.assertEqual(effects[SOCIAL + '/activities/c1'], 'created')
        self.assertEqual(effects[SOCIAL + '/activities/u1'], 'updated')
        self.assertEqual(effects[SOCIAL + '/activities/d1'], 'deleted')
        # Undo(Delete) 按因果顺序恢复，对象最终为 active
        self.assertEqual(obj['state'], 'active')
        self.assertEqual(obj['decision'], 'verified-state')
        # 坏签名收据中的伪造 Update 未参与归并
        self.assertNotIn(SOCIAL + '/activities/forged-update', effects)
        unverified = {u['activity_id']
                      for u in self.view['unverified_activities']}
        self.assertIn(SOCIAL + '/activities/forged-update', unverified)
        self.assertTrue(any('作者未核验' in r
                            for r in obj['decision_reasons']))

    def test_07_undo_announce_only_withdraws_forward(self):
        obj = next(o for o in self.view['objects']
                   if o['object_id'] == OBJ19)
        effects = {e['activity_id']: e['effect']
                   for e in obj['verified_basis']}
        self.assertEqual(effects[FRIEND_B + '/activities/b1'],
                         'forwarded-then-withdrawn')
        self.assertEqual(effects[FRIEND_B + '/activities/b2'],
                         'withdrew:' + FRIEND_B + '/activities/b1')
        # 原始 Announce 证据行仍在
        self.assertTrue(any(e['activity_id'] == FRIEND_B + '/activities/b1'
                            for e in obj['verified_basis']))

    def test_08_dangling_ref_then_late_resolution(self):
        # OBJ20 仅被转发，作者原文缺失：引用悬挂、对象 pending
        dangling = {p['object_id'] for p in self.view['dangling_refs']}
        self.assertIn(OBJ20, dangling)
        obj20 = next(o for o in self.view['objects']
                     if o['object_id'] == OBJ20)
        self.assertEqual(obj20['state'], 'pending')
        self.assertEqual(obj20['decision'], 'incomplete')

        # 迟到的作者收件箱收据带来 Create，引用闭合
        plan, replay = load_plan()
        late_items = [{
            'id': SOCIAL + '/activities/c20', 'type': 'Create',
            'actor': MEI, 'published': '2026-11-10T07:00:00Z',
            'object': {'id': OBJ20, 'type': 'Note',
                       'content': '迟到闭合的原文'}}]
        late_body = json.dumps(
            {'orderedItems': late_items}, ensure_ascii=False).encode()
        from tests.fixture_build import sign  # 复用测试签名助手
        late_headers = sign(
            SOCIAL + '/inbox-late', late_body,
            SOCIAL + '/users/mei#key', plan['keys'][SOCIAL + '/users/mei#key'])
        import base64
        replay['rows'].append({
            'request': {'method': 'GET', 'url': SOCIAL + '/inbox-late'},
            'response': {'status': 200, 'headers': late_headers,
                         'body_base64': base64.b64encode(late_body).decode()}})
        plan['endpoints'].append(
            {'role': 'inbox', 'url': SOCIAL + '/inbox-late'})
        c2, _ = run_collect(plan, replay)
        view2 = federation_overview(c2, plan['collection'])
        self.assertTrue(view2['all_refs_resolved'])
        obj20b = next(o for o in view2['objects']
                      if o['object_id'] == OBJ20)
        self.assertEqual(obj20b['state'], 'active')
        c2.close()

    def test_09_rerun_is_idempotent(self):
        plan, replay = load_plan()
        with tempfile.TemporaryDirectory() as t:
            db_path = str(Path(t) / 'journal.sqlite3')
            c1, _ = run_collect(plan, replay, db_path=db_path)
            v1 = federation_overview(c1, plan['collection'])
            c1.close()
            c2, _ = run_collect(plan, replay, db_path=db_path)
            v2 = federation_overview(c2, plan['collection'])
            c2.close()
        self.assertEqual(v1['counts'], v2['counts'])
        self.assertEqual(
            [(o['object_id'], o['state']) for o in v1['objects']],
            [(o['object_id'], o['state']) for o in v2['objects']])

    def test_10_status_explains_verified_basis(self):
        obj = next(o for o in self.view['objects']
                   if o['object_id'] == OBJ19)
        basis_ids = {e['receipt_id'] for e in obj['verified_basis']}
        # 每条依据都能回指具体已核验收据
        receipt_ids = {r['receipt_id'] for r in self.view['receipts']
                       if r['signature_ok']}
        self.assertTrue(basis_ids)
        self.assertTrue(basis_ids <= receipt_ids)
        # 投影明确列出仍悬而未决的引用
        self.assertTrue(any(p['object_id'] == OBJ20
                            for p in self.view['pending_refs']))


class RedirectEngineTest(unittest.TestCase):
    """传输引擎单测：异源剥离、同源保留、超限与错误。"""

    def test_cross_origin_hop_records_stripped(self):
        rows = [
            {'request': {'method': 'GET', 'url': 'https://a.test/x'},
             'response': {'status': 302,
                          'headers': {'location': 'https://b.test/y'},
                          'body_base64': ''}},
            {'request': {'method': 'GET', 'url': 'https://b.test/y',
                         'expect_headers_absent': ['authorization']},
             'response': {'status': 200, 'headers': {},
                          'body_base64': ''}},
        ]
        result = fetch(ReplayTransport(rows), 'https://a.test/x',
                       {'Authorization': 'Bearer z'})
        self.assertEqual(result.final_url, 'https://b.test/y')
        self.assertEqual(result.hops[0].stripped, ['authorization'])
        self.assertFalse(result.hops[0].authorization_forwarded)

    def test_same_origin_redirect_keeps_credentials(self):
        rows = [
            {'request': {'method': 'GET', 'url': 'https://a.test/x'},
             'response': {'status': 301,
                          'headers': {'location': 'https://a.test/y'},
                          'body_base64': ''}},
            {'request': {'method': 'GET', 'url': 'https://a.test/y'},
             'response': {'status': 200, 'headers': {},
                          'body_base64': ''}},
        ]
        result = fetch(ReplayTransport(rows), 'https://a.test/x',
                       {'Authorization': 'Bearer z'})
        self.assertEqual(result.hops[0].stripped, [])
        self.assertTrue(result.hops[0].authorization_forwarded)

    def test_network_error_is_result_not_exception(self):
        rows = [{'request': {'method': 'GET', 'url': 'https://a.test/x'},
                 'response': {'status': None, 'headers': {},
                              'body_base64': '',
                              'error': 'ConnectionError:拒绝'}}]
        result = fetch(ReplayTransport(rows), 'https://a.test/x')
        self.assertFalse(result.ok)
        self.assertIsNone(result.status)
        self.assertIn('ConnectionError', result.error)


if __name__ == '__main__':
    unittest.main()
