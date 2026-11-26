// Pure JavaScript BLAKE3-256 implementation matching the Rust `blake3` crate byte-for-byte.

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START = 1 << 0;
const CHUNK_END = 1 << 1;
const PARENT = 1 << 2;
const ROOT = 1 << 3;

function rotr32(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function g(state, a, b, c, d, mx, my) {
  state[a] = (state[a] + state[b] + mx) | 0;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) | 0;
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) | 0;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) | 0;
  state[b] = rotr32(state[b] ^ state[c], 7);
}

function roundFn(state, m) {
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

function permute(m) {
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = m[MSG_PERM[i]];
  }
  return out;
}

function compress(chainingValue, blockWords, counterLow, counterHigh, blockLen, flags) {
  const state = new Uint32Array([
    chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
    chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
    IV[0], IV[1], IV[2], IV[3],
    counterLow, counterHigh, blockLen, flags,
  ]);
  let m = new Uint32Array(blockWords);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m);

  for (let i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= chainingValue[i];
  }
  return state;
}

function wordsFromBytesLE(bytes, offset, len) {
  const words = new Uint32Array(16);
  for (let i = 0; i < len; i++) {
    words[i >> 2] |= bytes[offset + i] << ((i & 3) * 8);
  }
  return words;
}

function first8(state16) {
  return state16.slice(0, 8);
}

function parentCv(leftCv, rightCv, keyWords, flags) {
  const block = new Uint32Array(16);
  block.set(leftCv, 0);
  block.set(rightCv, 8);
  return first8(compress(keyWords, block, 0, 0, 64, flags | PARENT));
}

export function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") return new TextEncoder().encode(input);
  return new Uint8Array(input);
}

export function blake3Bytes(input) {
  const data = toBytes(input);
  const cvStack = [];

  if (data.length === 0) {
    const state = compress(IV, new Uint32Array(16), 0, 0, 0, CHUNK_START | CHUNK_END | ROOT);
    const out = new Uint8Array(32);
    const view = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) view.setUint32(i * 4, state[i] >>> 0, true);
    return out;
  }

  let chunkIdx = 0;
  let offset = 0;
  const totalLen = data.length;

  while (offset < totalLen) {
    const chunkEnd = Math.min(offset + 1024, totalLen);
    const isSingleChunk = chunkIdx === 0 && chunkEnd === totalLen;
    let cv = new Uint32Array(IV);
    let pos = offset;
    let blocksInChunk = 0;

    while (pos < chunkEnd || blocksInChunk === 0) {
      const rem = chunkEnd - pos;
      const take = Math.min(64, rem);
      const blockWords = wordsFromBytesLE(data, pos, take);
      let flags = 0;
      if (pos === offset) flags |= CHUNK_START;
      const isLastBlock = pos + take >= chunkEnd;
      if (isLastBlock) flags |= CHUNK_END;

      const cLow = chunkIdx >>> 0;
      const cHigh = Math.floor(chunkIdx / 0x100000000) >>> 0;

      if (isSingleChunk && isLastBlock) {
        flags |= ROOT;
        const state = compress(cv, blockWords, cLow, cHigh, take, flags);
        const out = new Uint8Array(32);
        const view = new DataView(out.buffer);
        for (let i = 0; i < 8; i++) view.setUint32(i * 4, state[i] >>> 0, true);
        return out;
      }

      cv = first8(compress(cv, blockWords, cLow, cHigh, take, flags));
      pos += take;
      blocksInChunk += 1;
    }

    offset = chunkEnd;
    chunkIdx += 1;

    if (offset < totalLen) {
      let totalChunks = chunkIdx;
      let newCv = cv;
      while ((totalChunks & 1) === 0) {
        newCv = parentCv(cvStack.pop(), newCv, IV, 0);
        totalChunks >>= 1;
      }
      cvStack.push(newCv);
    } else {
      // Final chunk in a multi-chunk tree
      const rightMost = cv;
      if (cvStack.length === 0) {
        const out = new Uint8Array(32);
        const view = new DataView(out.buffer);
        for (let i = 0; i < 8; i++) view.setUint32(i * 4, rightMost[i] >>> 0, true);
        return out;
      }
      let cur = rightMost;
      while (cvStack.length > 1) {
        cur = parentCv(cvStack.pop(), cur, IV, 0);
      }
      const left = cvStack.pop();
      const block = new Uint32Array(16);
      block.set(left, 0);
      block.set(cur, 8);
      const state = compress(IV, block, 0, 0, 64, PARENT | ROOT);
      const out = new Uint8Array(32);
      const view = new DataView(out.buffer);
      for (let i = 0; i < 8; i++) view.setUint32(i * 4, state[i] >>> 0, true);
      return out;
    }
  }
  return new Uint8Array(32);
}

export function blake3Hex(input) {
  const bytes = blake3Bytes(input);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}
