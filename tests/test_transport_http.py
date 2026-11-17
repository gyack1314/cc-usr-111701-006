"""真实 HTTP 回环：UrllibTransport 的重定向与认证剥离。

用标准库 ThreadingHTTPServer 在回环端口起两个“来源”，验证生产传输
与离线重放走同一套 fetch 引擎：302 到异源（异主机即异源）后，
Authorization 头不会被带到第二跳；网络失联返回结果而非异常。
"""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from capture_data.transport import UrllibTransport, fetch, origin_of


class _Handler(BaseHTTPRequestHandler):
    seen = {}

    def do_GET(self):
        host = self.headers.get('Host')
        type(self).seen.setdefault(host, []).append({
            'path': self.path,
            'authorization': self.headers.get('Authorization'),
            'cookie': self.headers.get('Cookie'),
        })
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', self.server.target_url)
            self.end_headers()
            return
        body = b'{"id":"https://a.test/objects/1"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/activity+json')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class UrllibLoopbackTest(unittest.TestCase):
    def setUp(self):
        _Handler.seen = {}
        self.server_a = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.server_b = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.port_a = self.server_a.server_address[1]
        self.port_b = self.server_b.server_address[1]
        # 端口不同 => 来源不同，触发异源剥离
        self.base_a = 'http://127.0.0.1:%d' % self.port_a
        self.base_b = 'http://127.0.0.1:%d' % self.port_b
        self.server_a.target_url = self.base_b + '/landing'
        for srv in (self.server_a, self.server_b):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
        self.addCleanup(self.server_a.shutdown)
        self.addCleanup(self.server_b.shutdown)
        self.addCleanup(self.server_a.server_close)
        self.addCleanup(self.server_b.server_close)

    def test_cross_origin_redirect_drops_authorization(self):
        self.assertNotEqual(origin_of(self.base_a), origin_of(self.base_b))
        transport = UrllibTransport(timeout=5)
        result = fetch(transport, self.base_a + '/redirect',
                       {'Authorization': 'Bearer secret',
                        'Cookie': 'session=1'})
        self.assertEqual(result.status, 200)
        self.assertEqual(result.final_url, self.base_b + '/landing')
        self.assertEqual(result.hops[0].stripped,
                         ['authorization', 'cookie'])
        # 第一跳携带认证
        first = _Handler.seen['127.0.0.1:%d' % self.port_a][0]
        self.assertEqual(first['authorization'], 'Bearer secret')
        # 异源第二跳收不到任何敏感头
        second = _Handler.seen['127.0.0.1:%d' % self.port_b][0]
        self.assertIsNone(second['authorization'])
        self.assertIsNone(second['cookie'])

    def test_connection_refused_is_error_result(self):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        port = srv.server_address[1]
        srv.server_close()  # 不启动，直接关闭 => 端口无人监听
        transport = UrllibTransport(timeout=2)
        result = fetch(transport, 'http://127.0.0.1:%d/inbox' % port)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.status)


if __name__ == '__main__':
    unittest.main()
