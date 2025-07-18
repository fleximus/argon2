module argon2

// Functional test file to test real-world usage scenarios
// This ensures the library works correctly in practical applications

fn test_basic_usage() {
	// Test basic Argon2id usage with real-world example
	password := 'my_secret_password'.bytes()
	salt := 'random_salt_12345'.bytes()
	
	// Hash with Argon2id (recommended variant)
	hash := hash_id_raw(3, 65536, 1, password, salt, 32) or {
		assert false, 'Basic hash should not fail: ${err}'
		return
	}
	
	// Verify hash properties
	assert hash.len == 32, 'Hash should be 32 bytes'
	
	// Test encoded version
	encoded := hash_id(3, 65536, 1, password, salt, 32) or {
		assert false, 'Encoded hash should not fail: ${err}'
		return
	}
	
	// Verify encoded format
	assert encoded.starts_with('\$argon2id\$v=19\$'), 'Should have correct prefix'
	assert encoded.contains('m=65536'), 'Should contain memory cost'
	assert encoded.contains('t=3'), 'Should contain time cost'
	assert encoded.contains('p=1'), 'Should contain parallelism'
	
}

fn test_parameter_sensitivity() {
	// Test that different parameters produce different hashes
	password := 'test_password'.bytes()
	salt := 'test_salt_123'.bytes()
	
	// Default parameters
	hash1 := hash_id_raw(3, 65536, 1, password, salt, 32) or {
		assert false, 'Hash1 should not fail'
		return
	}
	
	// Different memory cost
	hash2 := hash_id_raw(3, 1024, 1, password, salt, 32) or {
		assert false, 'Hash2 should not fail'
		return
	}
	
	// Different time cost
	hash3 := hash_id_raw(1, 65536, 1, password, salt, 32) or {
		assert false, 'Hash3 should not fail'
		return
	}
	
	// All hashes should be different
	assert hash1 != hash2, 'Different memory costs should produce different hashes'
	assert hash1 != hash3, 'Different time costs should produce different hashes'
	assert hash2 != hash3, 'All parameter variations should be unique'
	
}

fn test_salt_importance() {
	// Test that salt prevents rainbow table attacks
	password := 'common_password'.bytes()
	salt1 := 'salt_one_12345'.bytes()
	salt2 := 'salt_two_67890'.bytes()
	
	hash1 := hash_id_raw(2, 1024, 1, password, salt1, 32) or {
		assert false, 'Hash with salt1 should not fail'
		return
	}
	
	hash2 := hash_id_raw(2, 1024, 1, password, salt2, 32) or {
		assert false, 'Hash with salt2 should not fail'
		return
	}
	
	// Same password with different salts should produce different hashes
	assert hash1 != hash2, 'Same password with different salts should produce different hashes'
	
}

fn test_deterministic_behavior() {
	// Test that Argon2 is deterministic (same inputs = same outputs)
	password := 'deterministic_test'.bytes()
	salt := 'fixed_salt_value'.bytes()
	
	hash1 := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'First hash should not fail'
		return
	}
	
	hash2 := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Second hash should not fail'
		return
	}
	
	hash3 := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Third hash should not fail'
		return
	}
	
	// All hashes should be identical
	assert hash1 == hash2, 'Multiple runs should produce identical results'
	assert hash2 == hash3, 'Deterministic behavior should be consistent'
	
}

fn test_different_output_lengths() {
	// Test different hash output lengths
	password := 'length_test_pwd'.bytes()
	salt := 'length_test_salt'.bytes()
	
	// Test various output lengths
	lengths := [16, 32, 48, 64]
	mut hashes := [][]u8{}
	
	for length in lengths {
		hash := hash_id_raw(2, 1024, 1, password, salt, u32(length)) or {
			assert false, 'Hash with length ${length} should not fail'
			return
		}
		
		assert hash.len == length, 'Hash length should match requested length'
		hashes << hash
	}
	
	// All hashes should be different (different lengths = different outputs)
	for i in 0..hashes.len-1 {
		for j in i+1..hashes.len {
			assert hashes[i] != hashes[j], 'Different output lengths should produce different hashes'
		}
	}
	
}

fn test_input_validation() {
	// Test parameter validation
	password := 'valid_password'.bytes()
	salt := 'short'.bytes() // Too short salt (< 8 bytes)
	
	// This should fail due to short salt
	validate_parameters(2, 1024, 1, password, salt, 32) or {
		assert err.msg().contains('salt'), 'Should fail with salt error'
		return
	}
	
	assert false, 'Should have failed validation for short salt'
}