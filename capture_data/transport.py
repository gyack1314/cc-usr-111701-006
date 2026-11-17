"""联邦抓取传输层。

同一条重定向引擎同时服务于离线重放与真实 urllib 传输，保证
“重定向到异源时不转发认证信息”在测试与生产中走同一段代码。
网络失联返回带 error 的结果而不是抛出，由上层决定如何记录，
任何上层逻辑都不得把缺席解释成删除。
"""
from dataclasses import dataclass, field
from urllib import error as _urlerr
from urllib import request as _urlreq
import base64 as _b64
import urllib.parse as _urlparse

# 跨源重定向时必须剥离的敏感请求头（小写匹配）
SENSITIVE_HEADERS = ('authorization', 'cookie', 'proxy-authorization')
REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))


def origin_of(url):
    """返回规范化来源（scheme/host/port），用于异源判断。"""
    parts = _urlparse.urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError('URL 缺少主机: %r' % url)
    port = parts.port or (443 if parts.scheme.lower() == 'https' else 80)
    return '%s://%s:%d' % (parts.scheme.lower(), parts.hostname.lower(), port)


def redacted_headers(headers):
    """记录请求头时隐去敏感值，只保留是否出现过的事实。"""
    return {k: ('<redacted>' if k.lower() in SENSITIVE_HEADERS else v)
            for k, v in (headers or {}).items()}


@dataclass
class RawResponse:
    """单次请求、单跳的原始结果。"""
    requested_url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: bytes = b''
    error: str | None = None


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None
    origin: str
    authorization_forwarded: bool
    stripped: list


@dataclass
class FetchResult:
    """一次逻辑抓取的完整轨迹，最终地址与请求地址分列。"""
    requested_url: str
    final_url: str | None
    status: int | None
    headers: dict
    body: bytes
    hops: list
    error: str | None

    @property
    def ok(self):
        return self.error is None and self.status is not None and 200 <= self.status < 300


def fetch(transport, url, headers=None, max_redirects=5):
    """按重定向引擎抓取，异源跳转时剥离敏感请求头。"""
    headers = dict(headers or {})
    current = url
    hops = []
    for _ in range(max_redirects + 1):
        raw = transport.single_request('GET', current, headers)
        if raw.error is not None:
            return FetchResult(url, current, None, {}, b'', hops, raw.error)
        location = raw.headers.get('location') or raw.headers.get('Location')
        if raw.status in REDIRECT_STATUSES and location:
            target = _urlparse.urljoin(current, location)
            current_origin = origin_of(current)
            target_origin = origin_of(target)
            stripped = []
            if target_origin != current_origin:
                for name in list(headers):
                    if name.lower() in SENSITIVE_HEADERS:
                        stripped.append(name.lower())
                        del headers[name]
            hops.append(Hop(
                url=current,
                status=raw.status,
                location=target,
                origin=current_origin,
                authorization_forwarded=any(
                    k.lower() == 'authorization' for k in headers),
                stripped=stripped,
            ))
            current = target
            continue
        return FetchResult(url, current, raw.status,
                           dict(raw.headers), raw.body, hops, None)
    return FetchResult(url, current, None, {}, b'', hops, '重定向次数超限')


class ReplayTransport:
    """按冻结记录逐跳返回响应，并断言异源跳转没有带走认证。"""

    def __init__(self, rows):
        self.rows = list(rows)
        self.position = 0
        # 只记录隐去敏感值后的请求头，绝不留存令牌原文
        self.requests = []

    def single_request(self, method, url, headers=None):
        headers = dict(headers or {})
        self.requests.append({
            'method': method, 'url': url,
            'headers': redacted_headers(headers),
        })
        if self.position >= len(self.rows):
            raise EOFError('冻结响应已用完: %s %s' % (method, url))
        row = self.rows[self.position]
        expected = row['request']
        self.position += 1
        if (method, url) != (expected['method'], expected['url']):
            raise ValueError('请求与冻结记录不匹配: %s %s' % (method, url))
        present = {k.lower() for k in headers}
        for name in expected.get('expect_headers_absent', ()):
            if name.lower() in present:
                raise ValueError('敏感请求头 %s 被转发到异源' % name)
        resp = row['response']
        if resp.get('error'):
            return RawResponse(url, error=resp['error'])
        body = _b64.b64decode(resp.get('body_base64', ''))
        return RawResponse(url, status=resp['status'],
                           headers=dict(resp.get('headers', {})), body=body)


class _StopRedirects(_urlreq.HTTPRedirectHandler):
    """关闭 urllib 自动跳转，让统一的 fetch 引擎掌控认证剥离。"""

    def redirect_request(self, *args, **kwargs):
        return None


class UrllibTransport:
    """真实网络传输；单跳返回，重定向由 fetch() 统一处理。"""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.opener = _urlreq.build_opener(_StopRedirects())

    def single_request(self, method, url, headers=None):
        req = _urlreq.Request(url, headers=dict(headers or {}), method=method)
        try:
            resp = self.opener.open(req, timeout=self.timeout)
        except _urlerr.HTTPError as exc:
            # 3xx 被 _StopRedirects 拦成 HTTPError，这里还原成普通响应
            return RawResponse(url, exc.code, dict(exc.headers), exc.read())
        except (_urlerr.URLError, OSError) as exc:
            reason = exc.reason if isinstance(exc, _urlerr.URLError) else exc
            return RawResponse(url, error='%s:%s' % (type(reason).__name__, reason))
        with resp:
            return RawResponse(url, resp.status, dict(resp.headers), resp.read())
