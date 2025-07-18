module argon2

// Quick test to verify variants produce different results
fn test_variants_produce_different_results() {
	password := 'test123'.bytes()
	salt := 'saltsalt'.bytes()
	
	// Get hash from each variant
	hash_i := hash_i_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2i should work'
		return
	}
	
	hash_d := hash_d_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2d should work'
		return
	}
	
	hash_id := hash_id_raw(2, 1024, 1, password, salt, 32) or {
		assert false, 'Argon2id should work'
		return
	}
	
	// All variants should produce different results
	assert hash_i != hash_d, 'Argon2i and Argon2d should produce different hashes'
	assert hash_i != hash_id, 'Argon2i and Argon2id should produce different hashes'
	assert hash_d != hash_id, 'Argon2d and Argon2id should produce different hashes'
}