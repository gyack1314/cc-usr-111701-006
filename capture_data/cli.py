"""查看已接收资料的身份与本地引用，并驱动离线联邦采集。

inspect：沿用旧的冻结清单接收链路；
collect：按抓取计划走重放传输（或 urllib 传输）采集授权收件箱与
对象地址，输出联邦归并投影。离线合成样例不访问真实站点。
"""
import argparse
import json
import os
from pathlib import Path

from .io import load
from .domain import summarize
from .journal import connect, receive
from .projection import overview
from .federation import Collector
from .federation_view import federation_overview
from .transport import ReplayTransport, UrllibTransport
from .verification import HmacVerifier


def _load_json(path):
    return json.loads(
        Path(path).read_bytes().decode('utf-8'),
        parse_constant=lambda x: (_ for _ in ()).throw(
            ValueError('非有限JSON常量')))


def _cmd_inspect(args):
    path = Path(args.file)
    v, digest = load(path)
    summary = summarize(v, path.parent)
    c = connect(':memory:')
    source = receive(c, v, path.parent)
    print(json.dumps(
        {'manifest_sha256': digest, 'source_sha256': source,
         'summary': summary, 'overview': overview(c, v['collection'])},
        ensure_ascii=False, indent=2))
    c.close()


def _cmd_collect(args):
    path = Path(args.plan)
    plan = _load_json(path)
    collection = plan['collection']
    replay = _load_json(path.parent / plan['replay'])
    verifier = HmacVerifier(plan.get('keys') or {})
    if args.live:
        transport = UrllibTransport(timeout=args.timeout)
    else:
        transport = ReplayTransport(replay['rows'])
    # 认证令牌只从环境变量读取，绝不写入计划文件或仓库
    token = os.environ.get('COLLECTOR_AUTH_TOKEN')
    auth_headers = {'Authorization': 'Bearer ' + token} if token else {}
    c = connect(args.db or ':memory:')
    collector = Collector(transport, verifier, auth_headers)
    collector.collect(c, collection, plan)
    print(json.dumps(federation_overview(c, collection),
                     ensure_ascii=False, indent=2))
    c.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)

    p_inspect = sub.add_parser('inspect', help='查看冻结清单与本地引用')
    p_inspect.add_argument('file')
    p_inspect.set_defaults(func=_cmd_inspect)

    p_collect = sub.add_parser('collect', help='按抓取计划采集联邦收据')
    p_collect.add_argument('plan')
    p_collect.add_argument('--db', help='SQLite 账本路径，默认内存')
    p_collect.add_argument('--live', action='store_true',
                           help='使用真实 urllib 传输（默认离线重放）')
    p_collect.add_argument('--timeout', type=int, default=10)
    p_collect.set_defaults(func=_cmd_collect)

    a = p.parse_args()
    a.func(a)


if __name__ == '__main__':
    main()
