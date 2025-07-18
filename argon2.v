module argon2

import encoding.base64

// Main Argon2 implementation 
//
// This module provides a complete, RFC 9106 compliant implementation of the Argon2 
// password hashing algorithm in V language, including all three variants:
// - Argon2i: Data-independent (side-channel resistant)
// - Argon2d: Data-dependent (GPU resistant)  
// - Argon2id: Hybrid approach (recommended for most use cases)

// hash_id_raw generates a raw Argon2id hash
//
// Argon2id is the recommended variant for most applications as it combines
// the benefits of both Argon2i and Argon2d.
//
// Parameters:
//   t_cost: Number of iterations (time cost) - minimum 1, recommended 2-4
//   m_cost: Memory usage in KB - minimum 32, recommended 65536 (64MB)
//   parallelism: Number of parallel threads - minimum 1, recommended 1-4
//   password: Password bytes to hash
//   salt: Salt bytes (minimum 8 bytes, recommended 16+ bytes)
//   hashlen: Output hash length in bytes (minimum 4, recommended 32)
//
// Returns: Raw hash bytes or error
pub fn hash_id_raw(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) ![]u8 {
	// Validate parameters first
	validate_parameters(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create output buffer
	mut output := []u8{len: int(hashlen)}
	
	// Create Argon2 context
	mut ctx := Argon2Context{
		out: output
		outlen: hashlen
		pwd: pwd.clone()
		pwdlen: u32(pwd.len)
		salt: salt.clone()
		saltlen: u32(salt.len)
		secret: []u8{}
		secretlen: 0
		ad: []u8{}
		adlen: 0
		t_cost: t_cost
		m_cost: m_cost
		lanes: parallelism
		threads: parallelism
		version: u32(Argon2Version.version_number)
		flags: default_flags
	}
	
	// Run Argon2id algorithm
	argon2_ctx(mut ctx, Argon2Type.argon2_id)!
	
	return ctx.out.clone()
}

// hash_id generates an Argon2id hash in PHC string format
//
// This function generates a complete PHC string that includes all parameters
// and the hash, suitable for storage and later verification.
//
// Parameters: Same as hash_id_raw (hashlen is fixed at 32 bytes)
// Returns: PHC format string like "$argon2id$v=19$m=65536,t=2,p=1$salt$hash"  
pub fn hash_id(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) !string {
	// Get raw hash first
	hash := hash_id_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create encoded string in PHC format
	// $argon2id$v=19$m=65536,t=2,p=1$salt$hash
	salt_b64 := base64.encode(salt).trim_right('=')
	hash_b64 := base64.encode(hash).trim_right('=')
	
	encoded := '\$argon2id\$v=${int(Argon2Version.version_number)}\$m=${m_cost},t=${t_cost},p=${parallelism}\$${salt_b64}\$${hash_b64}'
	
	return encoded
}

// hash_i_raw generates a raw Argon2i hash
//
// Argon2i uses data-independent memory access patterns, making it resistant 
// to side-channel attacks. Use this variant in environments where timing
// attacks are a concern.
//
// Parameters: Same as hash_id_raw
// Returns: Raw hash bytes or error
pub fn hash_i_raw(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) ![]u8 {
	// Validate parameters first
	validate_parameters(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create output buffer
	mut output := []u8{len: int(hashlen)}
	
	// Create Argon2 context
	mut ctx := Argon2Context{
		out: output
		outlen: hashlen
		pwd: pwd.clone()
		pwdlen: u32(pwd.len)
		salt: salt.clone()
		saltlen: u32(salt.len)
		secret: []u8{}
		secretlen: 0
		ad: []u8{}
		adlen: 0
		t_cost: t_cost
		m_cost: m_cost
		lanes: parallelism
		threads: parallelism
		version: u32(Argon2Version.version_number)
		flags: default_flags
	}
	
	// Run Argon2i algorithm
	argon2_ctx(mut ctx, Argon2Type.argon2_i)!
	
	return ctx.out.clone()
}

// Argon2i encoded hash function  
pub fn hash_i(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) !string {
	// Get raw hash first
	hash := hash_i_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create encoded string in PHC format
	// $argon2i$v=19$m=65536,t=2,p=1$salt$hash
	salt_b64 := base64.encode(salt).trim_right('=')
	hash_b64 := base64.encode(hash).trim_right('=')
	
	encoded := '\$argon2i\$v=${int(Argon2Version.version_number)}\$m=${m_cost},t=${t_cost},p=${parallelism}\$${salt_b64}\$${hash_b64}'
	
	return encoded
}

// Argon2d raw hash function
pub fn hash_d_raw(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) ![]u8 {
	// Validate parameters first
	validate_parameters(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create output buffer
	mut output := []u8{len: int(hashlen)}
	
	// Create Argon2 context
	mut ctx := Argon2Context{
		out: output
		outlen: hashlen
		pwd: pwd.clone()
		pwdlen: u32(pwd.len)
		salt: salt.clone()
		saltlen: u32(salt.len)
		secret: []u8{}
		secretlen: 0
		ad: []u8{}
		adlen: 0
		t_cost: t_cost
		m_cost: m_cost
		lanes: parallelism
		threads: parallelism
		version: u32(Argon2Version.version_number)
		flags: default_flags
	}
	
	// Run Argon2d algorithm
	argon2_ctx(mut ctx, Argon2Type.argon2_d)!
	
	return ctx.out.clone()
}

// Argon2d encoded hash function  
pub fn hash_d(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) !string {
	// Get raw hash first
	hash := hash_d_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen)!
	
	// Create encoded string in PHC format
	// $argon2d$v=19$m=65536,t=2,p=1$salt$hash
	salt_b64 := base64.encode(salt).trim_right('=')
	hash_b64 := base64.encode(hash).trim_right('=')
	
	encoded := '\$argon2d\$v=${int(Argon2Version.version_number)}\$m=${m_cost},t=${t_cost},p=${parallelism}\$${salt_b64}\$${hash_b64}'
	
	return encoded
}

// hash is the simplest function for password hashing with secure defaults
//
// Uses Argon2id with recommended default parameters:
// - t=3 iterations (default_t_cost)
// - m=65536 (64 MB memory, default_m_cost) 
// - p=4 lanes (default_parallelism)
// - 16-byte salt (default_salt_len, 128 bits)
// - 32-byte output (default_hash_len, 256 bits)
//
// Parameters:
//   password: Password bytes to hash
//   salt: Salt bytes (must be at least 16 bytes for default security)
//
// Returns: PHC format string ready for storage and verification
pub fn hash(password []u8, salt []u8) !string {
	// Validate salt meets default requirements
	if salt.len < default_salt_len {
		return error('salt must be at least ${default_salt_len} bytes for default security')
	}
	
	return hash_id(default_t_cost, default_m_cost, default_parallelism, password, salt, default_hash_len)
}

// hash_with_params provides Argon2id hashing with custom parameters
//
// Uses Argon2id variant with user-specified parameters for fine-tuned security/performance.
// All parameters must be explicitly provided.
//
// Parameters:
//   t_cost: Number of iterations (time cost) - minimum 1, recommended 2-4
//   m_cost: Memory usage in KB - minimum 32, recommended 65536 (64MB)  
//   parallelism: Number of parallel threads - minimum 1, recommended 1-4
//   password: Password bytes to hash
//   salt: Salt bytes (minimum 8 bytes, recommended 16+ bytes)
//   hashlen: Output hash length in bytes (minimum 4, recommended 32)
//
// Returns: PHC format string ready for storage and verification
pub fn hash_with_params(t_cost u32, m_cost u32, parallelism u32, password []u8, salt []u8, hashlen u32) !string {
	return hash_id(t_cost, m_cost, parallelism, password, salt, hashlen)
}

// verify provides simple password verification against any Argon2 PHC string
//
// Automatically detects the Argon2 variant (i/d/id) from the PHC string and
// verifies the password using the appropriate algorithm and parameters.
//
// Parameters:
//   encoded: PHC format string (e.g., "$argon2id$v=19$m=65536,t=3,p=4$salt$hash")
//   password: Password bytes to verify
//
// Returns: true if password matches, false otherwise
pub fn verify(encoded string, password []u8) !bool {
	// Parse PHC string to determine the variant
	params := parse_phc_string(encoded)!
	
	// Use the appropriate verification function based on detected type
	result := match params.typ {
		.argon2_i { verify_i(encoded, password)! }
		.argon2_d { verify_d(encoded, password)! }
		.argon2_id { verify_id(encoded, password)! }
	}
	
	return result == int(Argon2ErrorCode.ok)
}

// Parameter validation function
pub fn validate_parameters(t_cost u32, m_cost u32, parallelism u32, pwd []u8, salt []u8, hashlen u32) ! {
	// Validate salt length
	if salt.len < min_salt_length {
		return error('salt too short')
	}
	
	// Validate output length
	if hashlen < min_outlen {
		return error('output too short')
	}
	
	if hashlen > max_outlen {
		return error('output too long')
	}
	
	// Validate time cost
	if t_cost < min_time {
		return error('time cost too small')
	}
	
	if t_cost > max_time {
		return error('time cost too large')
	}
	
	// Validate memory cost
	if m_cost < min_memory {
		return error('memory cost too small')
	}
	
	if m_cost > max_memory {
		return error('memory cost too large')
	}
	
	// Validate parallelism/lanes
	if parallelism < min_lanes {
		return error('too few lanes')
	}
	
	if parallelism > max_lanes {
		return error('too many lanes')
	}
	
	// Validate password length
	if pwd.len > max_pwd_length {
		return error('password too long')
	}
	
	// Validate salt length upper bound
	if salt.len > max_salt_length {
		return error('salt too long')
	}
}

// Error message helper
pub fn error_message(code Argon2ErrorCode) string {
	return match code {
		.ok { 'OK' }
		.output_ptr_null { 'Output pointer is NULL' }
		.output_too_short { 'Output is too short' }
		.output_too_long { 'Output is too long' }
		.pwd_too_short { 'Password is too short' }
		.pwd_too_long { 'Password is too long' }
		.salt_too_short { 'Salt is too short' }
		.salt_too_long { 'Salt is too long' }
		.time_too_small { 'Time cost is too small' }
		.time_too_large { 'Time cost is too large' }
		.memory_too_little { 'Memory cost is too small' }
		.memory_too_much { 'Memory cost is too large' }
		.lanes_too_few { 'Too few lanes' }
		.lanes_too_many { 'Too many lanes' }
		.verify_mismatch { 'The password does not match the supplied hash' }
		else { 'Unknown error code' }
	}
}

// Main Argon2 context function
pub fn argon2_ctx(mut ctx Argon2Context, typ Argon2Type) !int {
	// Validate context
	if ctx.outlen < min_outlen || ctx.outlen > max_outlen {
		return error('Invalid output length')
	}
	
	// Calculate memory blocks
	mut memory_blocks := ctx.m_cost
	if memory_blocks < 2 * sync_points * ctx.lanes {
		memory_blocks = 2 * sync_points * ctx.lanes
	}
	
	segment_length := memory_blocks / (ctx.lanes * sync_points)
	memory_blocks = segment_length * (ctx.lanes * sync_points)
	
	// Create instance
	mut instance := Argon2Instance{
		version: ctx.version
		passes: ctx.t_cost
		memory_blocks: memory_blocks
		segment_length: segment_length
		lane_length: segment_length * sync_points
		lanes: ctx.lanes
		threads: ctx.threads
		typ: typ
	}
	
	// Initialize memory
	result := initialize(mut instance, ctx)!
	if result != int(Argon2ErrorCode.ok) {
		return error('Initialization failed')
	}
	
	// Fill memory blocks
	fill_result := fill_memory_blocks(mut instance)
	if fill_result != int(Argon2ErrorCode.ok) {
		return error('Memory filling failed')
	}
	
	// Finalize
	finalize(mut ctx, instance)
	
	return int(Argon2ErrorCode.ok)
}


// Type to string conversion
pub fn type_to_string(typ Argon2Type, uppercase bool) string {
	base := match typ {
		.argon2_d { 'argon2d' }
		.argon2_i { 'argon2i' }
		.argon2_id { 'argon2id' }
	}
	
	if uppercase {
		return base.capitalize()
	}
	return base
}

// Verification functions for password hashes

// Verify password against Argon2i encoded hash
pub fn verify_i(encoded string, pwd []u8) !int {
	return argon2_verify(encoded, pwd, Argon2Type.argon2_i)
}

// Verify password against Argon2d encoded hash
pub fn verify_d(encoded string, pwd []u8) !int {
	return argon2_verify(encoded, pwd, Argon2Type.argon2_d)
}

// Verify password against Argon2id encoded hash
pub fn verify_id(encoded string, pwd []u8) !int {
	return argon2_verify(encoded, pwd, Argon2Type.argon2_id)
}

// Generic verification function
pub fn argon2_verify(encoded string, pwd []u8, expected_type Argon2Type) !int {
	// Parse the PHC string to extract parameters
	params := parse_phc_string(encoded)!
	
	// Verify the type matches
	if params.typ != expected_type {
		return error('Hash type mismatch')
	}
	
	// Recompute hash with extracted parameters
	computed_hash := match params.typ {
		.argon2_i {
			hash_i_raw(params.t_cost, params.m_cost, params.parallelism, pwd, params.salt, u32(params.hash.len))!
		}
		.argon2_d {
			hash_d_raw(params.t_cost, params.m_cost, params.parallelism, pwd, params.salt, u32(params.hash.len))!
		}
		.argon2_id {
			hash_id_raw(params.t_cost, params.m_cost, params.parallelism, pwd, params.salt, u32(params.hash.len))!
		}
	}
	
	
	// Compare hashes
	if computed_hash == params.hash {
		return int(Argon2ErrorCode.ok)
	} else {
		return int(Argon2ErrorCode.verify_mismatch)
	}
}

// Structure to hold parsed PHC parameters
struct PhcParams {
	typ         Argon2Type
	version     u32
	t_cost      u32
	m_cost      u32
	parallelism u32
	salt        []u8
	hash        []u8
}

// Add Base64 padding if needed for PHC format compatibility
fn add_base64_padding(s string) string {
	padding_needed := 4 - (s.len % 4)
	if padding_needed == 4 {
		return s // Already properly padded
	}
	return s + '='.repeat(padding_needed)
}

// Parse PHC format string: $argon2i$v=19$m=65536,t=2,p=1$salt$hash
fn parse_phc_string(encoded string) !PhcParams {
	// Split by '$' and remove empty first element
	parts := encoded.split('$').filter(it.len > 0)
	
	if parts.len != 5 {
		return error('Invalid PHC format: expected 5 parts, got ${parts.len}')
	}
	
	// Parse algorithm type
	typ := match parts[0] {
		'argon2i' { Argon2Type.argon2_i }
		'argon2d' { Argon2Type.argon2_d }
		'argon2id' { Argon2Type.argon2_id }
		else { return error('Unknown Argon2 type: ${parts[0]}') }
	}
	
	// Parse version
	version_part := parts[1]
	if !version_part.starts_with('v=') {
		return error('Invalid version format: ${version_part}')
	}
	version := version_part[2..].u32()
	
	// Parse parameters (m, t, p)
	params_part := parts[2]
	param_pairs := params_part.split(',')
	
	mut m_cost := u32(0)
	mut t_cost := u32(0)
	mut parallelism := u32(0)
	
	for pair in param_pairs {
		kv := pair.split('=')
		if kv.len != 2 {
			return error('Invalid parameter format: ${pair}')
		}
		
		key := kv[0]
		value := kv[1].u32()
		
		match key {
			'm' { m_cost = value }
			't' { t_cost = value }
			'p' { parallelism = value }
			else { return error('Unknown parameter: ${key}') }
		}
	}
	
	// Decode salt and hash from base64 (add padding if needed since PHC format omits it)
	salt_padded := add_base64_padding(parts[3])
	hash_padded := add_base64_padding(parts[4])
	salt := base64.decode(salt_padded)
	hash := base64.decode(hash_padded)
	
	return PhcParams{
		typ: typ
		version: version
		t_cost: t_cost
		m_cost: m_cost
		parallelism: parallelism
		salt: salt
		hash: hash
	}
}

