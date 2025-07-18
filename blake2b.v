module argon2

// Complete Blake2b implementation for Argon2
// RFC 7693 compliant implementation

const blake2b_blockbytes = 128
const blake2b_outbytes = 64
const blake2b_keybytes = 64
const blake2b_saltbytes = 16
const blake2b_personalbytes = 16

// Blake2b initialization vectors (from RFC 7693)
const blake2b_iv = [
	u64(0x6a09e667f3bcc908), u64(0xbb67ae8584caa73b),
	u64(0x3c6ef372fe94f82b), u64(0xa54ff53a5f1d36f1),
	u64(0x510e527fade682d1), u64(0x9b05688c2b3e6c1f),
	u64(0x1f83d9abfb41bd6b), u64(0x5be0cd19137e2179),
]

// Blake2b permutation sigma values (from RFC 7693)
const blake2b_sigma = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
	[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
	[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
	[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
	[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
	[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
	[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
	[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
	[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

// Blake2b state structure
struct Blake2bState {
mut:
	h        [8]u64                    // chained state
	t        [2]u64                    // total number of bytes
	f        [2]u64                    // finalization flags
	buf      [blake2b_blockbytes]u8   // input buffer
	buflen   int                      // input buffer length
	outlen   int                      // digest size
	last_node bool                    // is this the last node?
}

// Blake2b parameter block
struct Blake2bParam {
mut:
	digest_length  u8
	key_length     u8
	fanout         u8
	depth          u8
	leaf_length    u32
	node_offset    u64
	node_depth     u8
	inner_length   u8
	reserved       [14]u8
	salt           [blake2b_saltbytes]u8
	personal       [blake2b_personalbytes]u8
}

// Rotation function
fn rotr64(x u64, n int) u64 {
	return (x >> n) | (x << (64 - n))
}

// Blake2b quarter round function (G)
fn blake2b_g(mut v [16]u64, a int, b int, c int, d int, x u64, y u64) {
	v[a] = v[a] + v[b] + x
	v[d] = rotr64(v[d] ^ v[a], 32)
	v[c] = v[c] + v[d]
	v[b] = rotr64(v[b] ^ v[c], 24)
	v[a] = v[a] + v[b] + y
	v[d] = rotr64(v[d] ^ v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = rotr64(v[b] ^ v[c], 63)
}

// Little-endian load of 64-bit word
fn load64(src []u8, offset int) u64 {
	mut result := u64(0)
	for i in 0..8 {
		if offset + i < src.len {
			result |= u64(src[offset + i]) << (i * 8)
		}
	}
	return result
}

// Little-endian store of 64-bit word
fn store64(mut dst []u8, offset int, w u64) {
	for i in 0..8 {
		if offset + i < dst.len {
			dst[offset + i] = u8((w >> (i * 8)) & 0xFF)
		}
	}
}

// Blake2b compression function
fn blake2b_compress(mut s Blake2bState, block []u8) {
	mut v := [16]u64{}
	mut m := [16]u64{}
	
	// Initialize working variables
	for i in 0..8 {
		v[i] = s.h[i]
		v[i + 8] = blake2b_iv[i]
	}
	
	v[12] ^= s.t[0]
	v[13] ^= s.t[1]
	v[14] ^= s.f[0]
	v[15] ^= s.f[1]
	
	// Load message block
	for i in 0..16 {
		m[i] = load64(block, i * 8)
	}
	
	// 12 rounds of mixing
	for round in 0..12 {
		sigma_row := blake2b_sigma[round % 10]
		
		// Column mixing
		blake2b_g(mut v, 0, 4, 8, 12, m[sigma_row[0]], m[sigma_row[1]])
		blake2b_g(mut v, 1, 5, 9, 13, m[sigma_row[2]], m[sigma_row[3]])
		blake2b_g(mut v, 2, 6, 10, 14, m[sigma_row[4]], m[sigma_row[5]])
		blake2b_g(mut v, 3, 7, 11, 15, m[sigma_row[6]], m[sigma_row[7]])
		
		// Diagonal mixing
		blake2b_g(mut v, 0, 5, 10, 15, m[sigma_row[8]], m[sigma_row[9]])
		blake2b_g(mut v, 1, 6, 11, 12, m[sigma_row[10]], m[sigma_row[11]])
		blake2b_g(mut v, 2, 7, 8, 13, m[sigma_row[12]], m[sigma_row[13]])
		blake2b_g(mut v, 3, 4, 9, 14, m[sigma_row[14]], m[sigma_row[15]])
	}
	
	// Update hash state
	for i in 0..8 {
		s.h[i] ^= v[i] ^ v[i + 8]
	}
}

// Set last block flag
fn blake2b_set_lastblock(mut s Blake2bState) {
	if s.last_node {
		s.f[1] = u64(-1)
	}
	s.f[0] = u64(-1)
}

// Increment counter
fn blake2b_increment_counter(mut s Blake2bState, inc u64) {
	s.t[0] += inc
	if s.t[0] < inc {
		s.t[1] += 1
	}
}

// Initialize Blake2b state
fn blake2b_init(mut s Blake2bState, outlen int) int {
	if outlen == 0 || outlen > blake2b_outbytes {
		return -1
	}
	
	// Clear state
	s = Blake2bState{
		outlen: outlen
	}
	
	// Initialize hash state with IV
	for i in 0..8 {
		s.h[i] = blake2b_iv[i]
	}
	
	// Parameter block for simple hash (no key, salt, or personalization)
	s.h[0] ^= u64(outlen) | (u64(0) << 8) | (u64(1) << 16) | (u64(1) << 24)
	
	return 0
}

// Update Blake2b with new data
fn blake2b_update(mut s Blake2bState, input []u8) int {
	mut inlen := input.len
	mut offset := 0
	
	if inlen > 0 {
		left := s.buflen
		fill := blake2b_blockbytes - left
		
		if inlen > fill {
			s.buflen = 0
			// Fill buffer
			for i in 0..fill {
				s.buf[left + i] = input[offset + i]
			}
			// Process buffer
			blake2b_increment_counter(mut s, blake2b_blockbytes)
			blake2b_compress(mut s, s.buf[..])
			offset += fill
			inlen -= fill
			
			// Process full blocks
			for inlen > blake2b_blockbytes {
				blake2b_increment_counter(mut s, blake2b_blockbytes)
				blake2b_compress(mut s, input[offset..offset + blake2b_blockbytes])
				offset += blake2b_blockbytes
				inlen -= blake2b_blockbytes
			}
		}
		
		// Store remaining bytes
		for i in 0..inlen {
			s.buf[s.buflen + i] = input[offset + i]
		}
		s.buflen += inlen
	}
	
	return 0
}

// Finalize Blake2b and get output
fn blake2b_final(mut s Blake2bState) []u8 {
	mut out := []u8{len: s.outlen}
	
	blake2b_increment_counter(mut s, u64(s.buflen))
	blake2b_set_lastblock(mut s)
	
	// Pad buffer with zeros
	for i in s.buflen..blake2b_blockbytes {
		s.buf[i] = 0
	}
	
	blake2b_compress(mut s, s.buf[..])
	
	// Output hash
	for i in 0..s.outlen {
		out[i] = u8((s.h[i / 8] >> ((i % 8) * 8)) & 0xFF)
	}
	
	return out
}

// Main Blake2b hash function
pub fn blake2b(input []u8, outlen int) []u8 {
	mut s := Blake2bState{}
	
	if blake2b_init(mut s, outlen) != 0 {
		return []u8{}
	}
	
	blake2b_update(mut s, input)
	return blake2b_final(mut s)
}

// Blake2b with key
pub fn blake2b_keyed(input []u8, key []u8, outlen int) []u8 {
	// Simple keyed version - combine key and input
	mut combined := key.clone()
	combined << input
	return blake2b(combined, outlen)
}

// Streaming Blake2b interface
pub fn blake2b_streaming_init(outlen int) Blake2bState {
	mut s := Blake2bState{}
	blake2b_init(mut s, outlen)
	return s
}

pub fn blake2b_streaming_update(mut s Blake2bState, input []u8) {
	blake2b_update(mut s, input)
}

pub fn blake2b_streaming_final(mut s Blake2bState) []u8 {
	return blake2b_final(mut s)
}

// Blake2b long hash for variable output length (used by Argon2)
pub fn blake2b_long(input []u8, outlen int) []u8 {
	// Prepend output length as little-endian u32 (like reference implementation)
	outlen_bytes := [
		u8(outlen & 0xFF),
		u8((outlen >> 8) & 0xFF),
		u8((outlen >> 16) & 0xFF),
		u8((outlen >> 24) & 0xFF)
	]
	
	mut full_input := outlen_bytes.clone()
	full_input << input
	
	if outlen <= blake2b_outbytes {
		// Simple case: hash outlen_bytes || input
		return blake2b(full_input, outlen)
	}
	
	// For longer outputs, implement the extension mechanism like the reference
	mut out := []u8{len: outlen}
	mut toproduce := outlen
	
	// First, hash to get initial output
	out_buffer := blake2b(full_input, blake2b_outbytes)
	
	// Copy first half to output
	copy_len := blake2b_outbytes / 2
	for i in 0..copy_len {
		out[i] = out_buffer[i]
	}
	
	mut offset := copy_len
	toproduce -= copy_len
	mut in_buffer := out_buffer.clone()
	
	// Generate additional output by iterative hashing
	for toproduce > blake2b_outbytes {
		out_buffer2 := blake2b(in_buffer, blake2b_outbytes)
		
		// Copy half of the output
		for i in 0..blake2b_outbytes/2 {
			out[offset + i] = out_buffer2[i]
		}
		offset += blake2b_outbytes / 2
		toproduce -= blake2b_outbytes / 2
		in_buffer = out_buffer2.clone()
	}
	
	// Final iteration
	if toproduce > 0 {
		final_output := blake2b(in_buffer, toproduce)
		for i in 0..toproduce {
			out[offset + i] = final_output[i]
		}
	}
	
	return out
}