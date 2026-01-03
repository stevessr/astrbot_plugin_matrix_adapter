import hashlib
import hmac
import json


def _canonical_json(obj: dict) -> str:
    """生成 Matrix 规范的规范化 JSON"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_hkdf(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """计算 HKDF-SHA256"""
    # HKDF-Extract
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, input_key, hashlib.sha256).digest()

    # HKDF-Expand
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]
