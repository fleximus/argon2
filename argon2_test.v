module argon2

// Test-driven development for Argon2 implementation
// Starting with basic Argon2id functionality

fn test_argon2id_basic_hash() {
	// Test basic Argon2id functionality
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Test that the function runs without error
	result := hash_id_raw(2, 65536, 1, password, salt, 32) or {
		assert false, 'hash_id_raw should not fail: ${err}'
		return
	}
	
	// Basic validation tests
	assert result.len == 32, 'Hash length should be 32 bytes'
	
	// Test deterministic output (same input should give same output)
	result2 := hash_id_raw(2, 65536, 1, password, salt, 32) or {
		assert false, 'Second call should not fail'
		return
	}
	
	assert result == result2, 'Argon2 should be deterministic'
	
	// Test different inputs give different outputs
	different_password := 'different'.bytes()
	result3 := hash_id_raw(2, 65536, 1, different_password, salt, 32) or {
		assert false, 'Different password call should not fail'
		return
	}
	
	assert result != result3, 'Different passwords should give different hashes'
}

fn test_argon2id_encoded_hash() {
	// Test encoded hash generation
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Test encoded hash function
	encoded := hash_id(2, 65536, 1, password, salt, 32) or {
		assert false, 'hash_id should not fail: ${err}'
		return
	}
	
	// Should start with $argon2id$v=19$
	assert encoded.starts_with('\$argon2id\$v=19\$'), 'Encoded hash should have correct format'
	assert encoded.contains('m=65536'), 'Should contain memory parameter'
	assert encoded.contains('t=2'), 'Should contain time parameter' 
	assert encoded.contains('p=1'), 'Should contain parallelism parameter'
}

fn test_argon2_type_enum() {
	// Test that our enums are properly defined
	assert int(Argon2Type.argon2_d) == 0
	assert int(Argon2Type.argon2_i) == 1
	assert int(Argon2Type.argon2_id) == 2
}

fn test_argon2_version_enum() {
	// Test version enum
	assert Argon2Version.version_13 == Argon2Version.version_number
	assert int(Argon2Version.version_13) == 0x13
}

fn test_argon2_context_creation() {
	// Test that we can create and configure an Argon2Context
	mut ctx := Argon2Context{
		outlen: 32
		pwdlen: 8
		saltlen: 8
		t_cost: 2
		m_cost: 65536
		lanes: 1
		threads: 1
		version: u32(Argon2Version.version_number)
		flags: default_flags
	}
	
	assert ctx.outlen == 32
	assert ctx.t_cost == 2
	assert ctx.m_cost == 65536
	assert ctx.lanes == 1
}

fn test_argon2_constants() {
	// Test that constants are properly defined
	assert min_lanes == 1
	assert max_lanes == 0xFFFFFF
	assert sync_points == 4
	assert min_outlen == 4
	assert min_salt_length == 8
	assert default_t_cost == 3
	assert default_m_cost == 65536
}

fn test_parameter_validation() {
	// Test parameter validation (should fail gracefully)
	password := 'password'.bytes()
	salt := []u8{len: 4} // Salt too short
	
	// This should return an error for salt too short
	validate_parameters(2, 65536, 1, password, salt, 32) or {
		assert err.msg().contains('salt'), 'Should fail with salt error'
		return
	}
	
	// If we get here, validation passed when it shouldn't have
	assert false, 'Parameter validation should have failed for short salt'
}

// TDD: These tests will fail until we implement Argon2i functions
fn test_hash_i_raw() {
	// Test Argon2i raw hash function (data-independent variant)
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// This should fail initially as hash_i_raw doesn't exist yet
	result := hash_i_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'hash_i_raw should exist and work: ${err}'
		return
	}
	
	// Basic validation
	assert result.len == 32, 'Argon2i hash should be 32 bytes'
	
	// Test deterministic behavior
	result2 := hash_i_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Second Argon2i call should work'
		return
	}
	assert result == result2, 'Argon2i should be deterministic'
	
	// Test that Argon2i produces different result than Argon2id
	result_id := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2id comparison should work'
		return
	}
	assert result != result_id, 'Argon2i should produce different hash than Argon2id'
}

fn test_hash_i() {
	// Test Argon2i encoded hash function
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// This should fail initially as hash_i doesn't exist yet
	encoded := hash_i(2, 1024, 1, password, salt, 32) or {
		assert false, 'hash_i should exist and work: ${err}'
		return
	}
	
	// Test PHC format
	assert encoded.starts_with('\$argon2i\$v=19\$'), 'Should have correct Argon2i prefix'
	assert encoded.contains('m=1024'), 'Should contain memory parameter'
	assert encoded.contains('t=2'), 'Should contain time parameter'
	assert encoded.contains('p=1'), 'Should contain parallelism parameter'
}

// TDD: These tests will fail until we implement Argon2d functions
fn test_hash_d_raw() {
	// Test Argon2d raw hash function (data-dependent variant)
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// This should fail initially as hash_d_raw doesn't exist yet
	result := hash_d_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'hash_d_raw should exist and work: ${err}'
		return
	}
	
	// Basic validation
	assert result.len == 32, 'Argon2d hash should be 32 bytes'
	
	// Test deterministic behavior
	result2 := hash_d_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Second Argon2d call should work'
		return
	}
	assert result == result2, 'Argon2d should be deterministic'
	
	// Test that Argon2d produces different results than other variants
	result_i := hash_i_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2i comparison should work'
		return
	}
	result_id := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2id comparison should work'
		return
	}
	
	assert result != result_i, 'Argon2d should produce different hash than Argon2i'
	assert result != result_id, 'Argon2d should produce different hash than Argon2id'
}

fn test_hash_d() {
	// Test Argon2d encoded hash function
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// This should fail initially as hash_d doesn't exist yet
	encoded := hash_d(2, 1024, 1, password, salt, 32) or {
		assert false, 'hash_d should exist and work: ${err}'
		return
	}
	
	// Test PHC format
	assert encoded.starts_with('\$argon2d\$v=19\$'), 'Should have correct Argon2d prefix'
	assert encoded.contains('m=1024'), 'Should contain memory parameter'
	assert encoded.contains('t=2'), 'Should contain time parameter'
	assert encoded.contains('p=1'), 'Should contain parallelism parameter'
}

// TDD: These verification tests will fail until we implement verification functions
fn test_verify_i() {
	// Test Argon2i password verification
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Generate an encoded hash first
	encoded := hash_i(2, 1024, 1, password, salt, 32) or {
		assert false, 'Failed to generate encoded hash for verification test'
		return
	}
	
	// Verify with correct password - should succeed
	result := verify_i(encoded, password) or {
		assert false, 'verify_i should exist and work with correct password: ${err}'
		return
	}
	
	assert result == int(Argon2ErrorCode.ok), 'Verification should succeed with correct password'
	
	// Verify with wrong password - should fail
	wrong_password := 'wrongpassword'.bytes()
	result2 := verify_i(encoded, wrong_password) or {
		// This is expected to fail, but the function should exist
		assert err.msg().contains('mismatch') || err.msg().contains('verify'), 'Should fail with verification error'
		return
	}
	
	assert result2 != int(Argon2ErrorCode.ok), 'Verification should fail with wrong password'
}

fn test_verify_d() {
	// Test Argon2d password verification
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Generate an encoded hash first
	encoded := hash_d(2, 1024, 1, password, salt, 32) or {
		assert false, 'Failed to generate encoded hash for verification test'
		return
	}
	
	// Verify with correct password - should succeed
	result := verify_d(encoded, password) or {
		assert false, 'verify_d should exist and work with correct password: ${err}'
		return
	}
	
	assert result == int(Argon2ErrorCode.ok), 'Verification should succeed with correct password'
	
	// Verify with wrong password - should fail
	wrong_password := 'wrongpassword'.bytes()
	result2 := verify_d(encoded, wrong_password) or {
		// This is expected to fail, but the function should exist
		assert err.msg().contains('mismatch') || err.msg().contains('verify'), 'Should fail with verification error'
		return
	}
	
	assert result2 != int(Argon2ErrorCode.ok), 'Verification should fail with wrong password'
}

fn test_verify_id() {
	// Test Argon2id password verification
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Generate an encoded hash first
	encoded := hash_id(2, 1024, 1, password, salt, 32) or {
		assert false, 'Failed to generate encoded hash for verification test'
		return
	}
	
	// Verify with correct password - should succeed
	result := verify_id(encoded, password) or {
		assert false, 'verify_id should exist and work with correct password: ${err}'
		return
	}
	
	assert result == int(Argon2ErrorCode.ok), 'Verification should succeed with correct password'
	
	// Verify with wrong password - should fail
	wrong_password := 'wrongpassword'.bytes()
	result2 := verify_id(encoded, wrong_password) or {
		// This is expected to fail, but the function should exist
		assert err.msg().contains('mismatch') || err.msg().contains('verify'), 'Should fail with verification error'
		return
	}
	
	assert result2 != int(Argon2ErrorCode.ok), 'Verification should fail with wrong password'
}

fn test_generic_argon2_verify() {
	// Test generic argon2_verify function
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Test with Argon2id
	encoded_id := hash_id(2, 1024, 1, password, salt, 32) or {
		assert false, 'Failed to generate Argon2id hash'
		return
	}
	
	result := argon2_verify(encoded_id, password, Argon2Type.argon2_id) or {
		assert false, 'argon2_verify should exist and work: ${err}'
		return
	}
	
	assert result == int(Argon2ErrorCode.ok), 'Generic verify should work with Argon2id'
	
	// Test with wrong variant type - should fail
	result2 := argon2_verify(encoded_id, password, Argon2Type.argon2_i) or {
		// This might fail, which is expected
		assert err.msg().contains('mismatch') || err.msg().contains('type'), 'Should fail with type mismatch'
		return
	}
	
	assert result2 != int(Argon2ErrorCode.ok), 'Verification should fail with wrong variant type'
}

// Test default hash function with secure defaults
fn test_default_hash_with_secure_defaults() {
	password := 'my_secure_password'.bytes()
	salt := 'random_salt_16_b'.bytes() // 16 bytes for default security
	
	// Test default hash function
	encoded := hash(password, salt) or {
		assert false, 'Default hash should work: ${err}'
		return
	}
	
	// Should have correct prefix for argon2id
	assert encoded.starts_with('\$argon2id\$v=19\$'), 'Should be argon2id with correct version'
	
	// Should contain default parameters
	assert encoded.contains('m=65536'), 'Should use default memory cost'
	assert encoded.contains('t=3'), 'Should use default time cost'
	assert encoded.contains('p=4'), 'Should use default parallelism'
}

fn test_hash_with_params_custom_settings() {
	password := 'test_password'.bytes()
	salt := 'test_salt_123'.bytes()
	
	// Test hash_with_params function
	encoded := hash_with_params(2, 1024, 1, password, salt, 32) or {
		assert false, 'hash_with_params should work: ${err}'
		return
	}
	
	// Should have correct parameters
	assert encoded.contains('m=1024'), 'Should use specified memory cost'
	assert encoded.contains('t=2'), 'Should use specified time cost'
	assert encoded.contains('p=1'), 'Should use specified parallelism'
}

fn test_universal_verify_function() {
	password := 'verify_test_pwd'.bytes()
	salt := 'verify_test_salt'.bytes()
	
	// Create hashes with different variants
	encoded_id := hash_id(2, 1024, 1, password, salt, 32) or { panic(err) }
	encoded_i := hash_i(2, 1024, 1, password, salt, 32) or { panic(err) }
	encoded_d := hash_d(2, 1024, 1, password, salt, 32) or { panic(err) }
	
	// Test verify function with each variant
	result_id := verify(encoded_id, password) or { panic(err) }
	assert result_id == true, 'Should verify argon2id hash correctly'
	
	result_i := verify(encoded_i, password) or { panic(err) }
	assert result_i == true, 'Should verify argon2i hash correctly'
	
	result_d := verify(encoded_d, password) or { panic(err) }
	assert result_d == true, 'Should verify argon2d hash correctly'
	
	// Test with wrong password
	wrong_result := verify(encoded_id, 'wrong_password'.bytes()) or { panic(err) }
	assert wrong_result == false, 'Should reject wrong password'
}

fn test_default_salt_length_validation() {
	password := 'test_password'.bytes()
	short_salt := 'short'.bytes() // Less than 16 bytes
	
	// Should fail with short salt
	hash(password, short_salt) or {
		assert err.msg().contains('salt must be at least'), 'Should validate salt length'
		return
	}
	assert false, 'Should have failed with short salt'
}