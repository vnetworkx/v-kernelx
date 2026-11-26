package vnetworksdk

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
)

var blake3IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var msgPerm = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

const (
	flagChunkStart uint32 = 1 << 0
	flagChunkEnd   uint32 = 1 << 1
	flagParent     uint32 = 1 << 2
	flagRoot       uint32 = 1 << 3
)

func blake3G(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + my
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

func blake3Round(s *[16]uint32, m *[16]uint32) {
	blake3G(s, 0, 4, 8, 12, m[0], m[1])
	blake3G(s, 1, 5, 9, 13, m[2], m[3])
	blake3G(s, 2, 6, 10, 14, m[4], m[5])
	blake3G(s, 3, 7, 11, 15, m[6], m[7])
	blake3G(s, 0, 5, 10, 15, m[8], m[9])
	blake3G(s, 1, 6, 11, 12, m[10], m[11])
	blake3G(s, 2, 7, 8, 13, m[12], m[13])
	blake3G(s, 3, 4, 9, 14, m[14], m[15])
}

func permuteMsg(m *[16]uint32) {
	var tmp [16]uint32
	for i := 0; i < 16; i++ {
		tmp[i] = m[msgPerm[i]]
	}
	*m = tmp
}

func compress(cv [8]uint32, block [16]uint32, counter uint64, blockLen uint32, flags uint32) [16]uint32 {
	state := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}
	m := block
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m); permuteMsg(&m)
	blake3Round(&state, &m)
	for i := 0; i < 8; i++ {
		state[i] ^= state[i+8]
		state[i+8] ^= cv[i]
	}
	return state
}

func first8(s [16]uint32) [8]uint32 {
	var out [8]uint32
	copy(out[:], s[:8])
	return out
}

func wordsToBytesLE(words [8]uint32) [32]byte {
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], words[i])
	}
	return out
}

func wordsFromBytesLE(chunk []byte) [16]uint32 {
	var padded [64]byte
	copy(padded[:], chunk)
	var words [16]uint32
	for i := 0; i < 16; i++ {
		words[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	return words
}

func parentCV(left, right [8]uint32) [8]uint32 {
	var block [16]uint32
	copy(block[:8], left[:])
	copy(block[8:], right[:])
	return first8(compress(blake3IV, block, 0, 64, flagParent))
}

// Blake3Bytes computes the 32-byte BLAKE3-256 digest matching the Rust blake3 crate.
func Blake3Bytes(data []byte) [32]byte {
	totalLen := len(data)
	if totalLen == 0 {
		var zero [16]uint32
		return wordsToBytesLE(first8(compress(blake3IV, zero, 0, 0, flagChunkStart|flagChunkEnd|flagRoot)))
	}

	var cvStack [][8]uint32
	var chunkIdx uint64 = 0
	offset := 0

	for offset < totalLen {
		chunkEnd := offset + 1024
		if chunkEnd > totalLen {
			chunkEnd = totalLen
		}
		isSingle := chunkIdx == 0 && chunkEnd == totalLen
		cv := blake3IV
		pos := offset
		blocks := 0

		for pos < chunkEnd || blocks == 0 {
			take := chunkEnd - pos
			if take > 64 {
				take = 64
			}
			words := wordsFromBytesLE(data[pos : pos+take])
			var flags uint32
			if pos == offset {
				flags |= flagChunkStart
			}
			isLast := pos+take >= chunkEnd
			if isLast {
				flags |= flagChunkEnd
			}
			if isSingle && isLast {
				flags |= flagRoot
				return wordsToBytesLE(first8(compress(cv, words, chunkIdx, uint32(take), flags)))
			}
			cv = first8(compress(cv, words, chunkIdx, uint32(take), flags))
			pos += take
			blocks++
		}

		offset = chunkEnd
		chunkIdx++

		if offset < totalLen {
			totalChunks := chunkIdx
			newCV := cv
			for (totalChunks & 1) == 0 {
				left := cvStack[len(cvStack)-1]
				cvStack = cvStack[:len(cvStack)-1]
				newCV = parentCV(left, newCV)
				totalChunks >>= 1
			}
			cvStack = append(cvStack, newCV)
		} else {
			if len(cvStack) == 0 {
				return wordsToBytesLE(cv)
			}
			cur := cv
			for len(cvStack) > 1 {
				left := cvStack[len(cvStack)-1]
				cvStack = cvStack[:len(cvStack)-1]
				cur = parentCV(left, cur)
			}
			left := cvStack[0]
			var block [16]uint32
			copy(block[:8], left[:])
			copy(block[8:], cur[:])
			return wordsToBytesLE(first8(compress(blake3IV, block, 0, 64, flagParent|flagRoot)))
		}
	}
	return [32]byte{}
}

// Blake3Hex returns lowercase hex of the BLAKE3-256 digest.
func Blake3Hex(data []byte) string {
	b := Blake3Bytes(data)
	return hex.EncodeToString(b[:])
}
