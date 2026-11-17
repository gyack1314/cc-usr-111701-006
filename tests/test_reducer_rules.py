"""因果归并规则的纯单元测试：直接构造已封存活动表后调用 reduce。"""
import json
import unittest

from capture_data.federation import Collector
from capture_data.federation_view import federation_overview
from capture_data.journal import connect

COLLECTION = 'unit'
MEI = 'https://social.test/users/mei'
LI = 'https://friend.test/users/li'
OBJ = 'https://social.test/objects/1'


def _activity(c, aid, atype, actor, oid, published, verified=True,
              undo_target=None, receipt='r-1', order=1):
    payload = {'activity_id': aid, 'activity_type': atype, 'actor': actor,
               'object_id': oid, 'undo_target': undo_target}
    c.execute('INSERT INTO activities VALUES(?,?,?,?,?,?,?,?,?,?,?)', (
        COLLECTION, aid, atype, actor, oid, published, receipt, order,
        int(verified), '作者已核验' if verified else '收据未完成核验',
        json.dumps(payload, ensure_ascii=False)))


def _snapshot(c, oid, actor, verified=True, receipt='r-0', order=0):
    c.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?)', (
        COLLECTION, oid, 'Note', '内容', actor, receipt, order,
        int(verified)))


class ReducerRuleTest(unittest.TestCase):
    def test_update_after_tombstone_has_no_effect(self):
        c = connect(':memory:')
        _activity(c, 'a1', 'Create', MEI, OBJ, '2026-01-01T08:00:00Z', order=1)
        _activity(c, 'a2', 'Delete', MEI, OBJ, '2026-01-01T09:00:00Z', order=2)
        _activity(c, 'a3', 'Update', MEI, OBJ, '2026-01-01T10:00:00Z', order=3)
        Collector(None, None).reduce(c, COLLECTION)
        view = federation_overview(c, COLLECTION)
        obj = next(o for o in view['objects'] if o['object_id'] == OBJ)
        self.assertEqual(obj['state'], 'tombstone')
        self.assertTrue(any('晚于墓碑' in r for r in obj['decision_reasons']))
        effects = [e['effect'] for e in obj['verified_basis']]
        self.assertNotIn('updated', effects)

    def test_non_author_update_and_delete_rejected(self):
        c = connect(':memory:')
        _activity(c, 'a1', 'Create', MEI, OBJ, '2026-01-01T08:00:00Z', order=1)
        _activity(c, 'a2', 'Update', LI, OBJ, '2026-01-01T09:00:00Z', order=2)
        _activity(c, 'a3', 'Delete', LI, OBJ, '2026-01-01T10:00:00Z', order=3)
        Collector(None, None).reduce(c, COLLECTION)
        view = federation_overview(c, COLLECTION)
        obj = next(o for o in view['objects'] if o['object_id'] == OBJ)
        # 越权修订与删除都不生效，对象维持 Create 后的 active
        self.assertEqual(obj['state'], 'active')
        self.assertTrue(any('非作者' in r and 'Update' in r
                            for r in obj['decision_reasons']))
        self.assertTrue(any('非作者' in r and 'Delete' in r
                            for r in obj['decision_reasons']))

    def test_unverified_activity_never_changes_state(self):
        c = connect(':memory:')
        _snapshot(c, OBJ, MEI, verified=True)
        _activity(c, 'x1', 'Delete', MEI, OBJ, '2026-01-01T09:00:00Z',
                  verified=False, order=2)
        Collector(None, None).reduce(c, COLLECTION)
        view = federation_overview(c, COLLECTION)
        obj = next(o for o in view['objects'] if o['object_id'] == OBJ)
        self.assertEqual(obj['state'], 'active')
        self.assertEqual(len(view['unverified_activities']), 1)

    def test_re_reduce_is_deterministic(self):
        c = connect(':memory:')
        _activity(c, 'a1', 'Create', MEI, OBJ, '2026-01-01T08:00:00Z', order=1)
        _activity(c, 'a2', 'Delete', MEI, OBJ, '2026-01-01T09:00:00Z', order=2)
        reducer = Collector(None, None)
        reducer.reduce(c, COLLECTION)
        first = federation_overview(c, COLLECTION)
        reducer.reduce(c, COLLECTION)
        second = federation_overview(c, COLLECTION)
        self.assertEqual(
            [(o['object_id'], o['state']) for o in first['objects']],
            [(o['object_id'], o['state']) for o in second['objects']])

    def test_announce_without_author_record_stays_pending(self):
        c = connect(':memory:')
        _activity(c, 'f1', 'Announce', LI, OBJ, '2026-01-01T08:00:00Z', order=1)
        Collector(None, None).reduce(c, COLLECTION)
        view = federation_overview(c, COLLECTION)
        obj = next(o for o in view['objects'] if o['object_id'] == OBJ)
        self.assertEqual(obj['state'], 'pending')
        self.assertEqual(obj['decision'], 'incomplete')
        self.assertFalse(view['all_refs_resolved'])
        # 转发证据仍然保留
        self.assertEqual(obj['verified_basis'][0]['effect'], 'forwarded')

    def test_identity_change_and_recovery_same_object(self):
        """同身份变化（Update）与恢复（Undo Delete）都作用于同一 object_id。"""
        c = connect(':memory:')
        _activity(c, 'a1', 'Create', MEI, OBJ, '2026-01-01T08:00:00Z', order=1)
        _activity(c, 'a2', 'Update', MEI, OBJ, '2026-01-01T09:00:00Z', order=2)
        _activity(c, 'a3', 'Delete', MEI, OBJ, '2026-01-01T10:00:00Z', order=3)
        _activity(c, 'a4', 'Undo', MEI, OBJ, '2026-01-01T11:00:00Z',
                  undo_target='a3', order=4)
        Collector(None, None).reduce(c, COLLECTION)
        view = federation_overview(c, COLLECTION)
        objs = [o for o in view['objects'] if o['object_id'] == OBJ]
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['state'], 'active')
        chain = [e['effect'] for e in objs[0]['verified_basis']]
        self.assertEqual(chain, ['created', 'updated', 'deleted',
                                 'restored:a3'])


if __name__ == '__main__':
    unittest.main()
