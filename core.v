module argon2

// Remove unused import

// Core Argon2 implementation

// Memory block structure
struct Block {
mut:
	v [128]u64  // 1024 bytes = 128 x 64-bit words
}

// Working instance for Argon2 computation
struct Argon2Instance {
mut:
	version        u32
	memory         []Block    // Memory blocks
	passes         u32
	memory_blocks  u32
	segment_length u32
	lane_length    u32
	lanes          u32
	threads        u32
	typ            Argon2Type
}

// Generate initial hash H0 using streaming Blake2b (matches reference implementation)
fn initial_hash(ctx &Argon2Context, typ Argon2Type) []u8 {
	// Use streaming Blake2b exactly like the reference implementation
	mut blake_state := blake2b_streaming_init(64)  // ARGON2_PREHASH_DIGEST_LENGTH = 64
	
	// Hash parameters in the exact order as reference implementation
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.lanes))
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.outlen))
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.m_cost))
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.t_cost))
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.version))
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(u32(typ)))
	
	// Password length then password
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.pwdlen))
	if ctx.pwdlen > 0 {
		blake2b_streaming_update(mut blake_state, ctx.pwd)
	}
	
	// Salt length then salt
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.saltlen))
	if ctx.saltlen > 0 {
		blake2b_streaming_update(mut blake_state, ctx.salt)
	}
	
	// Secret length then secret
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.secretlen))
	if ctx.secretlen > 0 {
		blake2b_streaming_update(mut blake_state, ctx.secret)
	}
	
	// Associated data length then data
	blake2b_streaming_update(mut blake_state, u32_to_bytes_le(ctx.adlen))
	if ctx.adlen > 0 {
		blake2b_streaming_update(mut blake_state, ctx.ad)
	}
	
	return blake2b_streaming_final(mut blake_state)
}

// Initialize memory and first blocks
fn initialize(mut instance Argon2Instance, ctx &Argon2Context) !int {
	// Allocate memory blocks
	instance.memory = []Block{len: int(instance.memory_blocks)}
	
	// Generate initial hash H0 using the proper method
	h0 := initial_hash(ctx, instance.typ)
	
	// Create blockhash buffer like reference implementation
	// ARGON2_PREHASH_SEED_LENGTH = 72 (64 for H0 + 8 for counter and lane)
	mut blockhash := []u8{len: 72}
	
	// Copy H0 to first 64 bytes
	for i in 0..64 {
		blockhash[i] = h0[i]
	}
	
	// Generate first blocks for each lane using exact reference method
	for lane in 0..ctx.lanes {
		// First block: store counter=0 and lane at offset 64
		store32_le(mut blockhash, 64, 0)     // counter = 0
		store32_le(mut blockhash, 68, lane)  // lane number
		
		block1_hash := blake2b_long(blockhash, 1024)
		bytes_to_block(block1_hash, mut instance.memory[lane * instance.lane_length])
		
		// Second block: store counter=1 and lane at offset 64
		store32_le(mut blockhash, 64, 1)     // counter = 1
		store32_le(mut blockhash, 68, lane)  // lane number
		
		block2_hash := blake2b_long(blockhash, 1024)
		bytes_to_block(block2_hash, mut instance.memory[lane * instance.lane_length + 1])
	}
	
	return int(Argon2ErrorCode.ok)
}

// Fill memory blocks
fn fill_memory_blocks(mut instance Argon2Instance) int {
	// Main computation phases
	for pass in 0..instance.passes {
		for slice in 0..sync_points {
			for lane in 0..instance.lanes {
				fill_segment(mut instance, pass, lane, slice)
			}
		}
	}
	
	return int(Argon2ErrorCode.ok)
}

// Fill one segment of memory (exact reference implementation)
fn fill_segment(mut instance Argon2Instance, pass u32, lane u32, slice u32) {
	mut address_block := Block{}
	mut input_block := Block{}
	mut zero_block := Block{}
	
	mut prev_offset := u32(0)
	mut curr_offset := u32(0)
	mut starting_index := u32(0)
	
	// Determine if we use data-independent addressing
	data_independent_addressing := (instance.typ == Argon2Type.argon2_i) ||
		(instance.typ == Argon2Type.argon2_id && pass == 0 && slice < sync_points / 2)
	
	if data_independent_addressing {
		init_block_value(mut zero_block, 0)
		init_block_value(mut input_block, 0)
		
		input_block.v[0] = pass
		input_block.v[1] = lane
		input_block.v[2] = slice
		input_block.v[3] = instance.memory_blocks
		input_block.v[4] = instance.passes
		input_block.v[5] = u64(instance.typ)
	}
	
	starting_index = 0
	
	if pass == 0 && slice == 0 {
		starting_index = 2  // we have already generated the first two blocks
		
		// Don't forget to generate the first block of addresses
		if data_independent_addressing {
			next_addresses(mut address_block, mut input_block, zero_block)
		}
	}
	
	// Offset of the current block
	curr_offset = lane * instance.lane_length + slice * instance.segment_length + starting_index
	
	if curr_offset % instance.lane_length == 0 {
		// Last block in this lane
		prev_offset = curr_offset + instance.lane_length - 1
	} else {
		// Previous block
		prev_offset = curr_offset - 1
	}
	
	for i in starting_index..instance.segment_length {
		// 1.1 Rotating prev_offset if needed
		if curr_offset % instance.lane_length == 1 {
			prev_offset = curr_offset - 1
		}
		
		// 1.2.1 Taking pseudo-random value from the previous block
		mut pseudo_rand := u64(0)
		if data_independent_addressing {
			if i % addresses_in_block == 0 {
				next_addresses(mut address_block, mut input_block, zero_block)
			}
			pseudo_rand = address_block.v[i % addresses_in_block]
		} else {
			pseudo_rand = instance.memory[prev_offset].v[0]
		}
		
		// 1.2.2 Computing the lane of the reference block
		mut ref_lane := u32((pseudo_rand >> 32) % u64(instance.lanes))
		
		if pass == 0 && slice == 0 {
			// Can not reference other lanes yet
			ref_lane = lane
		}
		
		// 1.2.3 Computing the reference block index within the lane
		ref_index := index_alpha(instance, pass, slice, ref_lane, i, u32(pseudo_rand & 0xFFFFFFFF), ref_lane == lane)
		
		// 2 Creating a new block
		ref_block_offset := instance.lane_length * ref_lane + ref_index
		curr_block_offset := curr_offset
		
		if pass == 0 {
			fill_block(instance.memory[prev_offset], instance.memory[ref_block_offset], mut instance.memory[curr_block_offset], false)
		} else {
			fill_block(instance.memory[prev_offset], instance.memory[ref_block_offset], mut instance.memory[curr_block_offset], true)
		}
		
		curr_offset++
		prev_offset++
	}
}

// Exact implementation of index_alpha from reference C code
fn index_alpha(instance &Argon2Instance, pass u32, slice u32, lane u32, index u32, pseudo_rand u32, same_lane bool) u32 {
	// Calculate reference area size exactly as in reference implementation
	mut reference_area_size := u32(0)
	
	if pass == 0 {
		// First pass
		if slice == 0 {
			// First slice
			reference_area_size = index - 1  // all but the previous
		} else {
			if same_lane {
				// The same lane => add current segment
				reference_area_size = slice * instance.segment_length + index - 1
			} else {
				reference_area_size = slice * instance.segment_length + 
					if index == 0 { u32(-1) } else { 0 }
			}
		}
	} else {
		// Second pass
		if same_lane {
			reference_area_size = instance.lane_length - instance.segment_length + index - 1
		} else {
			reference_area_size = instance.lane_length - instance.segment_length +
				if index == 0 { u32(-1) } else { 0 }
		}
	}
	
	// Mapping pseudo_rand to 0..<reference_area_size-1> and produce relative position
	mut relative_position := u64(pseudo_rand)
	relative_position = relative_position * relative_position >> 32
	relative_position = u64(reference_area_size - 1) - 
		(u64(reference_area_size) * relative_position >> 32)
	
	// Computing starting position
	mut start_position := u32(0)
	if pass != 0 {
		start_position = if slice == sync_points - 1 {
			u32(0)
		} else {
			(slice + 1) * instance.segment_length
		}
	}
	
	// Computing absolute position
	absolute_position := (start_position + u32(relative_position)) % instance.lane_length
	return absolute_position
}

// fBlaMka function (designed by Lyra PHC team) - core of Argon2 compression
fn f_bla_mka(x u64, y u64) u64 {
	m := u64(0xFFFFFFFF)
	xy := (x & m) * (y & m)
	return x + y + 2 * xy
}


// G function - quarter round for Argon2 compression
fn argon2_g(a u64, b u64, c u64, d u64) (u64, u64, u64, u64) {
	mut a_new := f_bla_mka(a, b)
	mut d_new := rotr64(d ^ a_new, 32)
	mut c_new := f_bla_mka(c, d_new)
	mut b_new := rotr64(b ^ c_new, 24)
	a_new = f_bla_mka(a_new, b_new)
	d_new = rotr64(d_new ^ a_new, 16)
	c_new = f_bla_mka(c_new, d_new)
	b_new = rotr64(b_new ^ c_new, 63)
	return a_new, b_new, c_new, d_new
}

// Blake2 round without message for Argon2 compression
fn blake2_round_nomsg(mut v [16]u64) {
	// Column mixing
	v[0], v[4], v[8], v[12] = argon2_g(v[0], v[4], v[8], v[12])
	v[1], v[5], v[9], v[13] = argon2_g(v[1], v[5], v[9], v[13])
	v[2], v[6], v[10], v[14] = argon2_g(v[2], v[6], v[10], v[14])
	v[3], v[7], v[11], v[15] = argon2_g(v[3], v[7], v[11], v[15])
	
	// Diagonal mixing
	v[0], v[5], v[10], v[15] = argon2_g(v[0], v[5], v[10], v[15])
	v[1], v[6], v[11], v[12] = argon2_g(v[1], v[6], v[11], v[12])
	v[2], v[7], v[8], v[13] = argon2_g(v[2], v[7], v[8], v[13])
	v[3], v[4], v[9], v[14] = argon2_g(v[3], v[4], v[9], v[14])
}

// Proper Argon2 fill_block function (matches reference implementation)
fn fill_block(prev Block, ref Block, mut curr Block, with_xor bool) {
	// Create blockR = ref XOR prev
	mut block_r := Block{}
	mut block_tmp := Block{}
	
	// blockR = ref_block XOR prev_block
	for i in 0..128 {
		block_r.v[i] = ref.v[i] ^ prev.v[i]
		block_tmp.v[i] = block_r.v[i]  // Copy for later
	}
	
	// If with_xor, XOR with current block content
	if with_xor {
		for i in 0..128 {
			block_tmp.v[i] ^= curr.v[i]
		}
	}
	
	// Apply Blake2 rounds on columns (8 rounds of 16 elements each)
	for i in 0..8 {
		mut v := [16]u64{}
		start_idx := 16 * i
		
		// Load 16 consecutive elements
		for j in 0..16 {
			v[j] = block_r.v[start_idx + j]
		}
		
		// Apply Blake2 round
		blake2_round_nomsg(mut v)
		
		// Store back
		for j in 0..16 {
			block_r.v[start_idx + j] = v[j]
		}
	}
	
	// Apply Blake2 rounds on rows (8 rounds with specific pattern)
	for i in 0..8 {
		mut v := [16]u64{}
		
		// Load elements with row pattern: (0,1,16,17,...112,113), etc.
		v[0] = block_r.v[2 * i]
		v[1] = block_r.v[2 * i + 1]
		v[2] = block_r.v[2 * i + 16]
		v[3] = block_r.v[2 * i + 17]
		v[4] = block_r.v[2 * i + 32]
		v[5] = block_r.v[2 * i + 33]
		v[6] = block_r.v[2 * i + 48]
		v[7] = block_r.v[2 * i + 49]
		v[8] = block_r.v[2 * i + 64]
		v[9] = block_r.v[2 * i + 65]
		v[10] = block_r.v[2 * i + 80]
		v[11] = block_r.v[2 * i + 81]
		v[12] = block_r.v[2 * i + 96]
		v[13] = block_r.v[2 * i + 97]
		v[14] = block_r.v[2 * i + 112]
		v[15] = block_r.v[2 * i + 113]
		
		// Apply Blake2 round
		blake2_round_nomsg(mut v)
		
		// Store back with row pattern
		block_r.v[2 * i] = v[0]
		block_r.v[2 * i + 1] = v[1]
		block_r.v[2 * i + 16] = v[2]
		block_r.v[2 * i + 17] = v[3]
		block_r.v[2 * i + 32] = v[4]
		block_r.v[2 * i + 33] = v[5]
		block_r.v[2 * i + 48] = v[6]
		block_r.v[2 * i + 49] = v[7]
		block_r.v[2 * i + 64] = v[8]
		block_r.v[2 * i + 65] = v[9]
		block_r.v[2 * i + 80] = v[10]
		block_r.v[2 * i + 81] = v[11]
		block_r.v[2 * i + 96] = v[12]
		block_r.v[2 * i + 97] = v[13]
		block_r.v[2 * i + 112] = v[14]
		block_r.v[2 * i + 113] = v[15]
	}
	
	// Final step: copy block_tmp to curr, then XOR with blockR (matches reference)
	for i in 0..128 {
		curr.v[i] = block_tmp.v[i]
	}
	for i in 0..128 {
		curr.v[i] ^= block_r.v[i]
	}
}

// Finalize computation and extract result
fn finalize(mut ctx Argon2Context, instance &Argon2Instance) {
	// XOR last blocks of all lanes
	mut final_block := Block{}
	
	for lane in 0..ctx.lanes {
		last_block_pos := (lane + 1) * instance.lane_length - 1
		for i in 0..128 {
			final_block.v[i] ^= instance.memory[last_block_pos].v[i]
		}
	}
	
	// Extract output hash
	block_bytes := block_to_bytes(final_block)
	
	final_hash := blake2b_long(block_bytes, int(ctx.outlen))
	
	// Copy to output
	for i in 0..ctx.outlen {
		ctx.out[i] = final_hash[i]
	}
}

// Block utility functions

// Initialize block with a value (equivalent to init_block_value)
fn init_block_value(mut block Block, val u8) {
	fill_val := u64(val) | (u64(val) << 8) | (u64(val) << 16) | (u64(val) << 24) |
		(u64(val) << 32) | (u64(val) << 40) | (u64(val) << 48) | (u64(val) << 56)
	
	for i in 0..128 {
		block.v[i] = fill_val
	}
}

// Generate next addresses for data-independent addressing (exact reference implementation)
fn next_addresses(mut address_block Block, mut input_block Block, zero_block Block) {
	input_block.v[6]++
	fill_block(zero_block, input_block, mut address_block, false)
	fill_block(zero_block, address_block, mut address_block, false)
}

// Utility functions


// Convert u32 to little-endian bytes (matches reference implementation store32)
fn u32_to_bytes_le(val u32) []u8 {
	return [
		u8(val & 0xFF),
		u8((val >> 8) & 0xFF),
		u8((val >> 16) & 0xFF),
		u8((val >> 24) & 0xFF)
	]
}

// Legacy function for compatibility
fn u32_to_bytes(val u32) []u8 {
	return u32_to_bytes_le(val)
}

// Store u32 at specific offset in buffer (like reference store32)
fn store32_le(mut buffer []u8, offset int, val u32) {
	if offset + 4 <= buffer.len {
		buffer[offset] = u8(val & 0xFF)
		buffer[offset + 1] = u8((val >> 8) & 0xFF)
		buffer[offset + 2] = u8((val >> 16) & 0xFF)
		buffer[offset + 3] = u8((val >> 24) & 0xFF)
	}
}

// Convert bytes to block
fn bytes_to_block(bytes []u8, mut block Block) {
	for i in 0..128 {
		offset := i * 8
		if offset + 7 < bytes.len {
			block.v[i] = u64(bytes[offset]) |
				(u64(bytes[offset + 1]) << 8) |
				(u64(bytes[offset + 2]) << 16) |
				(u64(bytes[offset + 3]) << 24) |
				(u64(bytes[offset + 4]) << 32) |
				(u64(bytes[offset + 5]) << 40) |
				(u64(bytes[offset + 6]) << 48) |
				(u64(bytes[offset + 7]) << 56)
		}
	}
}

// Convert block to bytes
fn block_to_bytes(block Block) []u8 {
	mut result := []u8{len: 1024}
	
	for i in 0..128 {
		offset := i * 8
		val := block.v[i]
		result[offset] = u8(val & 0xFF)
		result[offset + 1] = u8((val >> 8) & 0xFF)
		result[offset + 2] = u8((val >> 16) & 0xFF)
		result[offset + 3] = u8((val >> 24) & 0xFF)
		result[offset + 4] = u8((val >> 32) & 0xFF)
		result[offset + 5] = u8((val >> 40) & 0xFF)
		result[offset + 6] = u8((val >> 48) & 0xFF)
		result[offset + 7] = u8((val >> 56) & 0xFF)
	}
	
	return result
}