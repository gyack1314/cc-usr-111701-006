"""生成带签名的合成联邦抓取夹具（仅测试/演示用，不访问真实站点）。

运行：python -I tests/fixture_build.py
产物：
  data/federation-plan.json   抓取计划（端点、HMAC 公钥索引）
  data/federation-replay.bin  冻结的逐跳 HTTP 响应记录
"""
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

# -I 隔离模式下 cwd 与 PYTHONPATH 均不进 sys.path，显式加入可信仓库根
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capture_data.verification import digest_header, signing_base

DATA = Path(__file__).resolve().parents[1] / 'data'

SOCIAL = 'https://social.example.test'
FRIEND_A = 'https://friend-a.example.test'
FRIEND_B = 'https://friend-b.example.test'
CDN = 'https://cdn-archive.example.net'

KEYS = {
    SOCIAL + '/users/mei#key': 'mei-shared-secret',
    FRIEND_A + '/users/li#key': 'li-shared-secret',
    FRIEND_B + '/users/wang#key': 'wang-shared-secret',
}
MEI = SOCIAL + '/users/mei'
LI = FRIEND_A + '/users/li'
WANG = FRIEND_B + '/users/wang'

OBJ19 = SOCIAL + '/objects/19'
OBJ20 = SOCIAL + '/objects/20'


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def sign(url, body, key_id, secret, method='GET', date='Thu, 12 Nov 2026 10:00:00 GMT'):
    """构造与 verification 模块一致的 Digest/Signature 响应头。"""
    digest = digest_header(body)
    headers = {'date': date, 'digest': digest}
    base = signing_base(method, url, headers,
                        ['(request-target)', 'host', 'date', 'digest'])
    sig = hmac.new(secret.encode(), base.encode(), hashlib.sha256).digest()
    headers['signature'] = (
        'keyId="%s",algorithm="hmac-sha256",'
        'headers="(request-target) host date digest",signature="%s"'
        % (key_id, _b64(sig)))
    headers['content-type'] = 'application/activity+json'
    return headers


def inbox_doc(items):
    return json.dumps({
        '@context': 'https://www.w3.org/ns/activitystreams',
        'orderedItems': items,
    }, ensure_ascii=False, indent=2).encode('utf-8')


def row(url, body, key_id, secret, status=200, extra_headers=None,
        expect_absent=()):
    headers = sign(url, body, key_id, secret)
    if extra_headers:
        headers.update(extra_headers)
    out = {'request': {'method': 'GET', 'url': url,
                       'expect_headers_absent': list(expect_absent)},
           'response': {'status': status, 'headers': headers,
                        'body_base64': _b64(body)}}
    return out


def redirect_row(url, location):
    return {'request': {'method': 'GET', 'url': url},
            'response': {'status': 302,
                         'headers': {'location': location},
                         'body_base64': ''}}


def main():
    rows = []

    # 1) 先到 friend-a：只有转发，合法签名（其发送者与作者不同源，
    #    仅可作为转发证据，不能对对象做修订/删除）
    a_items = [
        {'id': FRIEND_A + '/activities/a1', 'type': 'Announce',
         'actor': LI, 'published': '2026-11-10T09:30:00Z',
         'object': OBJ19},
        {'id': FRIEND_A + '/activities/a2', 'type': 'Announce',
         'actor': LI, 'published': '2026-11-10T09:35:00Z',
         'object': OBJ20},
    ]
    a_body = inbox_doc(a_items)
    rows.append(row(FRIEND_A + '/inbox', a_body,
                    FRIEND_A + '/users/li#key',
                    KEYS[FRIEND_A + '/users/li#key']))

    # 2) 坏签名收据：收据本身签名核验失败，其中的作者修订必须被拒绝
    forged_items = [
        {'id': SOCIAL + '/activities/forged-update', 'type': 'Update',
         'actor': MEI, 'published': '2026-11-10T09:40:00Z',
         'object': OBJ19},
    ]
    forged = row(FRIEND_A + '/inbox-alt', inbox_doc(forged_items),
                 FRIEND_A + '/users/li#key',
                 KEYS[FRIEND_A + '/users/li#key'])
    bad = dict(forged['response']['headers'])
    bad['signature'] = bad['signature'].rsplit('"', 2)[0] + 'AAAAAAAAAAAAAAAA"'
    forged['response']['headers'] = bad
    rows.append(forged)

    # 2) 作者实例 social 的收件箱：Create -> Update -> Delete -> Undo(Delete)
    s_items = [
        {'id': SOCIAL + '/activities/c1', 'type': 'Create',
         'actor': MEI, 'published': '2026-11-10T08:00:00Z',
         'object': {'id': OBJ19, 'type': 'Note', 'content': '公开消息'}},
        {'id': SOCIAL + '/activities/u1', 'type': 'Update',
         'actor': MEI, 'published': '2026-11-10T09:00:00Z',
         'object': {'id': OBJ19, 'type': 'Note', 'content': '修订消息'}},
        {'id': SOCIAL + '/activities/d1', 'type': 'Delete',
         'actor': MEI, 'published': '2026-11-10T10:00:00Z',
         'object': OBJ19},
        {'id': SOCIAL + '/activities/r1', 'type': 'Undo',
         'actor': MEI, 'published': '2026-11-10T11:00:00Z',
         'object': {'id': SOCIAL + '/activities/d1', 'type': 'Delete'}},
    ]
    rows.append(row(SOCIAL + '/inbox', inbox_doc(s_items),
                    SOCIAL + '/users/mei#key',
                    KEYS[SOCIAL + '/users/mei#key']))

    # 3) friend-b：另一条 Announce 及其 Undo（撤回转发，不删证据）
    b_items = [
        {'id': FRIEND_B + '/activities/b1', 'type': 'Announce',
         'actor': WANG, 'published': '2026-11-10T09:45:00Z',
         'object': OBJ19},
        {'id': FRIEND_B + '/activities/b2', 'type': 'Undo',
         'actor': WANG, 'published': '2026-11-10T12:00:00Z',
         'object': {'id': FRIEND_B + '/activities/b1', 'type': 'Announce'}},
    ]
    rows.append(row(FRIEND_B + '/inbox', inbox_doc(b_items),
                    FRIEND_B + '/users/wang#key',
                    KEYS[FRIEND_B + '/users/wang#key']))

    # 4) 失联实例：错误响应，缺席不得被当作删除
    rows.append({
        'request': {'method': 'GET',
                    'url': 'https://down.example.test/inbox'},
        'response': {'status': None, 'headers': {}, 'body_base64': '',
                     'error': 'ConnectionError:连接被拒绝'}})

    # 5) 对象地址：同源授权请求被 302 到异源 CDN，认证头必须剥离
    rows.append(redirect_row(SOCIAL + '/objects/19', CDN + '/mirror/19'))
    obj_doc = json.dumps({
        'id': OBJ19, 'type': 'Note', 'content': '修订消息',
        'attributedTo': MEI,
    }, ensure_ascii=False, indent=2).encode('utf-8')
    rows.append(row(CDN + '/mirror/19', obj_doc,
                    SOCIAL + '/users/mei#key',
                    KEYS[SOCIAL + '/users/mei#key'],
                    expect_absent=['authorization', 'cookie']))

    replay = {'kind': 'federation-replay', 'rows': rows}
    replay_raw = json.dumps(replay, ensure_ascii=False, indent=2).encode('utf-8')
    (DATA / 'federation-replay.bin').write_bytes(replay_raw)

    plan = {
        'kind': 'federation-fetch-plan',
        'protocol': 'activitypub-feed',
        'collection': 'federation-sample',
        'replay': 'federation-replay.bin',
        'keys': KEYS,
        'endpoints': [
            {'role': 'inbox', 'url': FRIEND_A + '/inbox'},
            {'role': 'inbox', 'url': FRIEND_A + '/inbox-alt'},
            {'role': 'inbox', 'url': SOCIAL + '/inbox'},
            {'role': 'inbox', 'url': FRIEND_B + '/inbox'},
            {'role': 'inbox', 'url': 'https://down.example.test/inbox'},
            {'role': 'object', 'url': SOCIAL + '/objects/19'},
        ],
    }
    (DATA / 'federation-plan.json').write_text(
        json.dumps(plan, ensure_ascii=False, indent=2), encoding='utf-8')
    print('wrote', DATA / 'federation-plan.json')
    print('wrote', DATA / 'federation-replay.bin', len(replay_raw), 'bytes')


if __name__ == '__main__':
    main()
