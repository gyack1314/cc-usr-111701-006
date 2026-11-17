"""联邦档案的对外投影：状态、核验依据、悬而未决引用与失联实例。"""
import hashlib
import json


def federation_overview(c, collection):
    receipt_cols = ('receipt_id', 'endpoint_role', 'requested_url',
                    'final_url', 'origin', 'status', 'error', 'body',
                    'headers', 'hops', 'digest_ok', 'signature_ok',
                    'verification')
    receipts = []
    for row in c.execute(
            'SELECT receipt_id,endpoint_role,requested_url,final_url,origin,'
            'status,error,body,headers,hops,digest_ok,signature_ok,'
            'verification FROM receipts WHERE collection=? '
            'ORDER BY received_order', (collection,)):
        d = dict(zip(receipt_cols, row))
        receipts.append({
            'receipt_id': d['receipt_id'],
            'endpoint_role': d['endpoint_role'],
            'requested_url': d['requested_url'],
            'final_url': d['final_url'],
            'origin': d['origin'],
            'status': d['status'],
            'error': d['error'],
            'body_sha256': hashlib.sha256(d['body']).hexdigest(),
            'body_bytes': len(d['body']),
            'hops': json.loads(d['hops']),
            'digest_ok': bool(d['digest_ok']),
            'signature_ok': bool(d['signature_ok']),
            'verification': json.loads(d['verification']),
        })
    instances = [dict(origin=r[0], reachable=bool(r[1]),
                      last_status=r[2], last_error=r[3],
                      checked_receipt_id=r[4])
                 for r in c.execute(
                     'SELECT origin,reachable,last_status,last_error,'
                     'checked_receipt_id FROM instances '
                     'WHERE collection=? ORDER BY origin', (collection,))]
    objects = [dict(object_id=r[0], state=r[1], summary=r[2],
                    updated_by_activity=r[3], decision=r[4],
                    decision_reasons=json.loads(r[5]))
               for r in c.execute(
                   'SELECT object_id,state,summary,updated_by_activity,'
                   'decision,decision_reasons FROM objects '
                   'WHERE collection=? ORDER BY object_id', (collection,))]
    evidence = [dict(object_id=r[0], activity_id=r[1],
                     activity_type=r[2], actor=r[3], receipt_id=r[4],
                     effect=r[5])
                for r in c.execute(
                    'SELECT object_id,activity_id,activity_type,actor,'
                    'receipt_id,effect FROM object_evidence '
                    'WHERE collection=? ORDER BY object_id,rowid',
                    (collection,))]
    pending = [dict(object_id=r[0], referenced_by_activity=r[1],
                    origin=r[2], resolved=bool(r[3]), note=r[4])
               for r in c.execute(
                   'SELECT object_id,referenced_by_activity,origin,resolved,'
                   'note FROM pending_refs WHERE collection=? '
                   'ORDER BY resolved,object_id', (collection,))]
    unverified = [dict(activity_id=r[0], activity_type=r[1], actor=r[2],
                       object_id=r[3], receipt_id=r[4], detail=r[5])
                  for r in c.execute(
                      'SELECT activity_id,activity_type,actor,object_id,'
                      'receipt_id,verification_detail FROM activities '
                      'WHERE collection=? AND actor_verified=0 '
                      'ORDER BY activity_id', (collection,))]

    # 每个对象的显示状态建立在哪些已核验活动/快照上
    basis = {}
    for e in evidence:
        basis.setdefault(e['object_id'], []).append(e)
    for obj in objects:
        obj['verified_basis'] = basis.get(obj['object_id'], [])

    dangling = [p for p in pending if not p['resolved']]
    unreachable = [i for i in instances if not i['reachable']]
    return {
        'collection': collection,
        'receipts': receipts,
        'instances': instances,
        'objects': objects,
        'unverified_activities': unverified,
        'pending_refs': pending,
        'dangling_refs': dangling,
        'unreachable_instances': unreachable,
        'counts': {
            'receipts': len(receipts),
            'instances': len(instances),
            'objects': len(objects),
            'evidence_rows': len(evidence),
            'unverified_activities': len(unverified),
            'dangling_refs': len(dangling),
            'unreachable_instances': len(unreachable),
        },
        'all_refs_resolved': not dangling,
    }
