module argon2

// Test Blake2b implementation against known test vectors
fn test_blake2b_basic() {
	// Blake2b test vector for empty input with 64-byte output
	// From RFC 7693 Appendix A
	input := []u8{}
	expected_hex := '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
	
	result := blake2b(input, 64)
	
	expected_bytes := hex_to_bytes(expected_hex)
	assert result == expected_bytes, 'Blake2b should match RFC 7693 test vector'
}

// Test Blake2b with "The quick brown fox jumps over the lazy dog"
fn test_blake2b_fox_dog() {
	input := 'The quick brown fox jumps over the lazy dog'.bytes()
	expected_hex := 'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918'
	
	result := blake2b(input, 64)
	
	expected_bytes := hex_to_bytes(expected_hex)
	assert result == expected_bytes, 'Blake2b should match expected hash for fox/dog text'
}

// Test Blake2b with "The quick brown fox jumps over the lazy dof" (note: dof not dog)
fn test_blake2b_fox_dof() {
	input := 'The quick brown fox jumps over the lazy dof'.bytes()
	expected_hex := 'ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb'
	
	result := blake2b(input, 64)
	
	expected_bytes := hex_to_bytes(expected_hex)
	assert result == expected_bytes, 'Blake2b should match expected hash for fox/dof text'
}

// Helper function to convert hex string to bytes
fn hex_to_bytes(hex_str string) []u8 {
	mut result := []u8{}
	for i := 0; i < hex_str.len; i += 2 {
		if i + 1 < hex_str.len {
			hex_byte := hex_str[i..i+2]
			byte_val := u8(hex_byte.parse_uint(16, 8) or { 0 })
			result << byte_val
		}
	}
	return result
}

// Helper function to convert bytes to hex
fn bytes_to_hex(data []u8) string {
	mut result := ''
	for b in data {
		result += '${b:02x}'
	}
	return result
}