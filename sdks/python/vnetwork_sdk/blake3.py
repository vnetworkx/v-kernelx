"""Pure-Python BLAKE3-256 implementation matching Rust's blake3 crate byte-for-byte."""

import struct
from typing import List, Union

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
MASK32 = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _g(state: List[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK32
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK32
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _round_fn(state: List[int], m: List[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    cv: List[int],
    block_words: List[int],
    counter_low: int,
    counter_high: int,
    block_len: int,
    flags: int,
) -> List[int]:
    state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low & MASK32, counter_high & MASK32, block_len & MASK32, flags & MASK32,
    ]
    m = list(block_words)
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m); m = [m[i] for i in MSG_PERM]
    _round_fn(state, m)
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def _words_from_bytes_le(chunk: bytes) -> List[int]:
    padded = chunk + b"\x00" * (64 - len(chunk))
    return list(struct.unpack("<16I", padded))


def _parent_cv(left_cv: List[int], right_cv: List[int]) -> List[int]:
    block = left_cv + right_cv
    return _compress(IV, block, 0, 0, 64, PARENT)[:8]


def _words_to_bytes_le(words: List[int]) -> bytes:
    return struct.pack("<8I", *words[:8])


def blake3_bytes(data: Union[bytes, bytearray, str]) -> bytes:
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = bytes(data)

    total_len = len(raw)
    if total_len == 0:
        state = _compress(IV, [0] * 16, 0, 0, 0, CHUNK_START | CHUNK_END | ROOT)
        return _words_to_bytes_le(state)

    cv_stack: List[List[int]] = []
    chunk_idx = 0
    offset = 0

    while offset < total_len:
        chunk_end = min(offset + 1024, total_len)
        is_single = chunk_idx == 0 and chunk_end == total_len
        cv = list(IV)
        pos = offset
        blocks_in_chunk = 0

        while pos < chunk_end or blocks_in_chunk == 0:
            take = min(64, chunk_end - pos)
            words = _words_from_bytes_le(raw[pos : pos + take])
            flags = 0
            if pos == offset:
                flags |= CHUNK_START
            is_last_block = (pos + take) >= chunk_end
            if is_last_block:
                flags |= CHUNK_END
            c_low = chunk_idx & MASK32
            c_high = (chunk_idx >> 32) & MASK32
            if is_single and is_last_block:
                flags |= ROOT
                state = _compress(cv, words, c_low, c_high, take, flags)
                return _words_to_bytes_le(state)
            cv = _compress(cv, words, c_low, c_high, take, flags)[:8]
            pos += take
            blocks_in_chunk += 1

        offset = chunk_end
        chunk_idx += 1

        if offset < total_len:
            total_chunks = chunk_idx
            new_cv = cv
            while (total_chunks & 1) == 0:
                new_cv = _parent_cv(cv_stack.pop(), new_cv)
                total_chunks >>= 1
            cv_stack.append(new_cv)
        else:
            if not cv_stack:
                return _words_to_bytes_le(cv)
            cur = cv
            while len(cv_stack) > 1:
                cur = _parent_cv(cv_stack.pop(), cur)
            left = cv_stack.pop()
            state = _compress(IV, left + cur, 0, 0, 64, PARENT | ROOT)
            return _words_to_bytes_le(state)

    return b"\x00" * 32


def blake3_hex(data: Union[bytes, bytearray, str]) -> str:
    try:
        import vnetwork_native  # type: ignore

        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        return vnetwork_native.blake3_digest_hex(raw)
    except Exception:
        return blake3_bytes(data).hex()
