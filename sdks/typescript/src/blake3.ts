const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START = 1 << 0;
const CHUNK_END = 1 << 1;
const PARENT = 1 << 2;
const ROOT = 1 << 3;

function rotr32(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

function g(state: Uint32Array, a: number, b: number, c: number, d: number, mx: number, my: number): void {
  state[a] = (state[a] + state[b] + mx) | 0;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) | 0;
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) | 0;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) | 0;
  state[b] = rotr32(state[b] ^ state[c], 7);
}

function roundFn(state: Uint32Array, m: Uint32Array): void {
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

function permute(m: Uint32Array): Uint32Array {
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) out[i] = m[MSG_PERM[i]];
  return out;
}

function compress(
  cv: Uint32Array,
  blockWords: Uint32Array,
  counterLow: number,
  counterHigh: number,
  blockLen: number,
  flags: number
): Uint32Array {
  const state = new Uint32Array([
    cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
    IV[0], IV[1], IV[2], IV[3], counterLow, counterHigh, blockLen, flags,
  ]);
  let m: Uint32Array = new Uint32Array(blockWords);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m); m = permute(m);
  roundFn(state, m);

  for (let i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= cv[i];
  }
  return state;
}

function wordsFromBytesLE(bytes: Uint8Array, offset: number, len: number): Uint32Array {
  const words = new Uint32Array(16);
  for (let i = 0; i < len; i++) {
    words[i >> 2] |= bytes[offset + i] << ((i & 3) * 8);
  }
  return words;
}

function parentCv(leftCv: Uint32Array, rightCv: Uint32Array): Uint32Array {
  const block = new Uint32Array(16);
  block.set(leftCv, 0);
  block.set(rightCv, 8);
  return compress(IV, block, 0, 0, 64, PARENT).slice(0, 8);
}

export function blake3Bytes(input: Uint8Array | string): Uint8Array {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const cvStack: Uint32Array[] = [];

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
    let cv: Uint32Array = new Uint32Array(IV);
    let pos = offset;
    let blocksInChunk = 0;

    while (pos < chunkEnd || blocksInChunk === 0) {
      const take = Math.min(64, chunkEnd - pos);
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

      cv = compress(cv, blockWords, cLow, cHigh, take, flags).slice(0, 8);
      pos += take;
      blocksInChunk += 1;
    }

    offset = chunkEnd;
    chunkIdx += 1;

    if (offset < totalLen) {
      let totalChunks = chunkIdx;
      let newCv: Uint32Array = cv;
      while ((totalChunks & 1) === 0) {
        newCv = parentCv(cvStack.pop()!, newCv);
        totalChunks >>= 1;
      }
      cvStack.push(newCv);
    } else {
      let cur: Uint32Array = cv;
      if (cvStack.length === 0) {
        const out = new Uint8Array(32);
        const view = new DataView(out.buffer);
        for (let i = 0; i < 8; i++) view.setUint32(i * 4, cur[i] >>> 0, true);
        return out;
      }
      while (cvStack.length > 1) {
        cur = parentCv(cvStack.pop()!, cur);
      }
      const left = cvStack.pop()!;
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

export function blake3Hex(input: Uint8Array | string): string {
  const bytes = blake3Bytes(input);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}
