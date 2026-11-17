"""收据验证：字节摘要与请求级签名分开核验。

- RFC 3230 风格 Digest 头：证明响应体字节与送达内容一致；
- HTTP Signature 草案风格 Signature 头：证明某个密钥持有者签过
  (request-target)、host、date 与 digest。

真实部署可接入非对称加密后端实现 SignatureVerifier；内置 HMAC
实现覆盖同样的验证语义，使无第三方依赖的合成与离线场景可复现。
验证器永远不会“信任” actor 字段，它只确认签名事实；发送者与
作者的授权关系在领域归并层另行判断。
"""
import base64
import hashlib
import hmac
import urllib.parse as _urlparse
from dataclasses import dataclass, field

from .transport import origin_of


def _b64(value):
    return base64.b64encode(value).decode('ascii')


def digest_header(body):
    """生成 RFC 3230 风格的 SHA-256 摘要头。"""
    return 'SHA-256=' + _b64(hashlib.sha256(body).digest())


def verify_digest(headers, body):
    """核对响应头中的摘要与字节体。"""
    raw = headers.get('digest') or headers.get('Digest')
    if not raw:
        return False, '缺少 Digest 头'
    for part in raw.split(','):
        name, _, value = part.strip().partition('=')
        if name.lower() != 'sha-256':
            continue
        try:
            expected = base64.b64decode(value.strip(), validate=True)
        except Exception:
            return False, 'Digest 头编码非法'
        actual = hashlib.sha256(body).digest()
        if hmac.compare_digest(expected, actual):
            return True, '摘要匹配'
        return False, '摘要不匹配'
    return False, 'Digest 头不含 SHA-256'


def parse_signature_header(value):
    """解析 keyId="...",algorithm="...",headers="...",signature="..."。"""
    out = {}
    key = None
    token = []
    quoted = False
    for ch in value:
        if quoted:
            if ch == '"':
                quoted = False
            else:
                token.append(ch)
            continue
        if ch == '"':
            quoted = True
        elif ch == '=':
            key = ''.join(token).strip()
            token = []
        elif ch == ',':
            if key is not None:
                out[key] = ''.join(token)
            key, token = None, []
        else:
            token.append(ch)
    if key is not None:
        out[key] = ''.join(token)
    return out


def signing_base(method, url, headers, signed_headers):
    """按签名头列表构造签名基串，主机名取自实际请求 URL。"""
    lowered = {k.lower(): v for k, v in headers.items()}
    parts = _urlparse.urlsplit(url)
    lowered.setdefault('host', parts.netloc)
    lines = []
    for name in signed_headers:
        name = name.lower()
        if name == '(request-target)':
            target = parts.path or '/'
            if parts.query:
                target += '?' + parts.query
            lines.append('(request-target): %s %s' % (method.lower(), target))
        else:
            if name not in lowered:
                raise ValueError('签名缺少请求头: %s' % name)
            lines.append('%s: %s' % (name, lowered[name].strip()))
    return '\n'.join(lines)


class HmacVerifier:
    """按 keyId URL 查找共享密钥的 HMAC 验证器（合成/测试实现）。"""

    def __init__(self, keys=None):
        self.keys = dict(keys or {})

    def verify(self, key_id, signing_base, signature_b64):
        secret = self.keys.get(key_id)
        if secret is None:
            return False, '未知 keyId: %s' % key_id
        try:
            given = base64.b64decode(signature_b64, validate=True)
        except Exception:
            return False, '签名编码非法'
        calc = hmac.new(secret.encode('utf-8'),
                        signing_base.encode('utf-8'), hashlib.sha256).digest()
        if hmac.compare_digest(given, calc):
            return True, 'HMAC 签名匹配'
        return False, 'HMAC 签名不匹配'


@dataclass
class ReceiptVerification:
    digest_ok: bool
    digest_detail: str
    signature_ok: bool
    signature_detail: str
    key_id: str | None = None
    signed_headers: list = field(default_factory=list)
    signed_by_origin: str | None = None

    @property
    def verified(self):
        return self.digest_ok and self.signature_ok


def verify_receipt(transport_method, url, headers, body, verifier):
    """完整验证一条响应收据；任何一步失败都给出原因，绝不静默放行。"""
    digest_ok, digest_detail = verify_digest(headers, body)
    sig_raw = headers.get('signature') or headers.get('Signature')
    if not sig_raw:
        return ReceiptVerification(
            digest_ok, digest_detail, False, '缺少 Signature 头')
    try:
        params = parse_signature_header(sig_raw)
        signed_headers = (params.get('headers') or
                          'date').lower().split()
        base = signing_base(transport_method, url, headers, signed_headers)
    except ValueError as exc:
        return ReceiptVerification(
            digest_ok, digest_detail, False, '签名基串构造失败: %s' % exc)
    key_id = params.get('keyId')
    signature = params.get('signature')
    if not key_id or not signature:
        return ReceiptVerification(
            digest_ok, digest_detail, False, 'Signature 头缺 keyId/signature',
            key_id=key_id, signed_headers=signed_headers)
    sig_ok, sig_detail = verifier.verify(key_id, base, signature)
    signed_by_origin = None
    if sig_ok:
        try:
            signed_by_origin = origin_of(key_id)
        except ValueError:
            signed_by_origin = None
    return ReceiptVerification(
        digest_ok, digest_detail, sig_ok, sig_detail,
        key_id=key_id, signed_headers=signed_headers,
        signed_by_origin=signed_by_origin)
