"""Pure-Python RFC 8032 Ed25519 implementation (extended twisted Edwards coordinates)."""

import hashlib
from typing import Tuple

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(z: int) -> int:
    return pow(z, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_B_EXT = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)
_IDENT_EXT = (0, 1, 1, 0)


def _edwards_add(p: Tuple[int, int, int, int], q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (t1 * 2 * _D * t2) % _Q
    dd = (z1 * 2 * z2) % _Q
    e = (b - a) % _Q
    f = (dd - c) % _Q
    g = (dd + c) % _Q
    h = (b + a) % _Q
    return ((e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q)


def _edwards_double(p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    return _edwards_add(p, p)


def _scalarmult(p: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    res = _IDENT_EXT
    cur = p
    k = e
    while k > 0:
        if k & 1:
            res = _edwards_add(res, cur)
        cur = _edwards_double(cur)
        k >>= 1
    return res


def _encodepoint(p: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    xp = (x * zi) % _Q
    yp = (y * zi) % _Q
    bits = yp | ((xp & 1) << 255)
    return bits.to_bytes(32, "little")


def _clamp_scalar(h_first_32: bytes) -> int:
    arr = bytearray(h_first_32)
    arr[0] &= 248
    arr[31] &= 127
    arr[31] |= 64
    return int.from_bytes(arr, "little")


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp_scalar(h[:32])
    return _encodepoint(_scalarmult(_B_EXT, a))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp_scalar(h[:32])
    prefix = h[32:64]
    a_pub = _encodepoint(_scalarmult(_B_EXT, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_pt = _encodepoint(_scalarmult(_B_EXT, r))
    k = int.from_bytes(hashlib.sha512(r_pt + a_pub + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_pt + s.to_bytes(32, "little")


def _decodepoint(enc: bytes) -> Tuple[int, int, int, int]:
    if len(enc) != 32:
        raise ValueError("Ed25519 point encoding must be 32 bytes")
    if enc == bytes(32) or enc == (b"\x01" + bytes(31)):
        raise ValueError("Weak or identity Ed25519 point rejected")
    y_int = int.from_bytes(enc, "little")
    sign_bit = (y_int >> 255) & 1
    y = y_int & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("Non-canonical Ed25519 y coordinate")
    xx = ((y * y - 1) * _inv(_D * y * y + 1)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q != 0:
        raise ValueError("Point is not on Ed25519 curve")
    if x == 0 and sign_bit == 1:
        raise ValueError("Non-canonical Ed25519 negative zero x coordinate")
    if (x & 1) != sign_bit:
        x = _Q - x
    return (x, y, 1, (x * y) % _Q)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("Invalid Ed25519 public key or signature length")
    a_pt = _decodepoint(public_key)
    r_bytes = signature[:32]
    r_pt = _decodepoint(r_bytes)
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        raise ValueError("Non-canonical Ed25519 signature scalar")
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    lhs = _encodepoint(_scalarmult(_B_EXT, s))
    rhs = _encodepoint(_edwards_add(r_pt, _scalarmult(a_pt, k)))
    if lhs != rhs:
        raise ValueError("Invalid Ed25519 signature")
    return True
