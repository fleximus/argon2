module argon2

// Official test vectors from the reference implementation
// Based on phc-winner-argon2/src/test.c

// Helper function to convert hex string to bytes for comparison
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

// Helper function to convert bytes to hex string for debugging
fn bytes_to_hex(data []u8) string {
	mut result := ''
	for b in data {
		result += '${b:02x}'
	}
	return result
}

// Test the user-provided test vector first
fn test_user_provided_vector() {
	// Input = "Lorem ipsum", Salt = "q7isXKjZJVfKRmSe", Parallelism Factor = 2, 
	// Memory Cost = 16, Iterations = 2, Hash Length = 16 
	// Expected: Hex_Output = "c2e1b651dde4f514eb7d226c36f54ce6"
	// Expected: Encoded_Output = "$argon2i$v=19$m=16,t=2,p=2$cTdpc1hLalpKVmZLUm1TZQ$wuG2Ud3k9RTrfSJsNvVM5g"
	
	password := 'Lorem ipsum'.bytes()
	salt := 'q7isXKjZJVfKRmSe'.bytes()
	expected_hex := 'c2e1b651dde4f514eb7d226c36f54ce6'
	expected_encoded := r'$argon2i$v=19$m=16,t=2,p=2$cTdpc1hLalpKVmZLUm1TZQ$wuG2Ud3k9RTrfSJsNvVM5g'
	
	// Test raw hash
	result := hash_i_raw(2, 16, 2, password, salt, 16) or {
		assert false, 'User test vector should not fail: ${err}'
		return
	}
	
	expected_bytes := hex_to_bytes(expected_hex)
	
	assert result == expected_bytes, 'User test vector hash should match expected output'
	
	// Test encoded hash
	encoded := hash_i(2, 16, 2, password, salt, 16) or {
		assert false, 'User test vector encoded should not fail: ${err}'
		return
	}
	
	
	assert encoded == expected_encoded, 'User test vector encoded should match expected format'
	
}

// Argon2i test vectors from official test.c (version 19)
fn test_argon2i_official_vectors_v19() {
	
	// Test case 1: Basic test
	// t=2, m=65536, p=1, password="password", salt="somesalt"
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	expected_hex := 'c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0'
	expected_encoded := r'$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA'
	
	result := hash_i_raw(2, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2i basic test should not fail: ${err}'
		return
	}
	
	expected_bytes := hex_to_bytes(expected_hex)
	
	assert result == expected_bytes, 'Argon2i basic test should match expected hash'
	
	encoded := hash_i(2, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2i basic encoded should not fail: ${err}'
		return
	}
	
	assert encoded == expected_encoded, 'Argon2i basic encoded should match expected format'
	
	// Test case 2: Low memory (m=256)
	expected_hex2 := '89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f'
	expected_encoded2 := r'$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8'
	
	result2 := hash_i_raw(2, 256, 1, password, salt, 32) or {
		assert false, 'Argon2i low memory test should not fail: ${err}'
		return
	}
	
	expected_bytes2 := hex_to_bytes(expected_hex2)
	
	assert result2 == expected_bytes2, 'Argon2i low memory test should match expected hash'
	
	encoded2 := hash_i(2, 256, 1, password, salt, 32) or {
		assert false, 'Argon2i low memory encoded should not fail: ${err}'
		return
	}
	
	assert encoded2 == expected_encoded2, 'Argon2i low memory encoded should match expected format'
	
	// Test case 3: Parallel (p=2)
	expected_hex3 := '4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61'
	expected_encoded3 := r'$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E'
	
	result3 := hash_i_raw(2, 256, 2, password, salt, 32) or {
		assert false, 'Argon2i parallel test should not fail: ${err}'
		return
	}
	
	expected_bytes3 := hex_to_bytes(expected_hex3)
	
	assert result3 == expected_bytes3, 'Argon2i parallel test should match expected hash'
	
	encoded3 := hash_i(2, 256, 2, password, salt, 32) or {
		assert false, 'Argon2i parallel encoded should not fail: ${err}'
		return
	}
	
	assert encoded3 == expected_encoded3, 'Argon2i parallel encoded should match expected format'
	
}

// Argon2id test vectors from official test.c (version 19)  
fn test_argon2id_official_vectors_v19() {
	
	// Test case 1: Basic test
	// t=2, m=65536, p=1, password="password", salt="somesalt"
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	expected_hex := '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
	expected_encoded := r'$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc'
	
	result := hash_id_raw(2, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2id basic test should not fail: ${err}'
		return
	}
	
	expected_bytes := hex_to_bytes(expected_hex)
	
	assert result == expected_bytes, 'Argon2id basic test should match expected hash'
	
	encoded := hash_id(2, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2id basic encoded should not fail: ${err}'
		return
	}
	
	assert encoded == expected_encoded, 'Argon2id basic encoded should match expected format'
	
	// Test case 2: Low memory (m=256) 
	expected_hex2 := '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe'
	expected_encoded2 := r'$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4'
	
	result2 := hash_id_raw(2, 256, 1, password, salt, 32) or {
		assert false, 'Argon2id low memory test should not fail: ${err}'
		return
	}
	
	expected_bytes2 := hex_to_bytes(expected_hex2)
	
	assert result2 == expected_bytes2, 'Argon2id low memory test should match expected hash'
	
	encoded2 := hash_id(2, 256, 1, password, salt, 32) or {
		assert false, 'Argon2id low memory encoded should not fail: ${err}'
		return
	}
	
	assert encoded2 == expected_encoded2, 'Argon2id low memory encoded should match expected format'
	
}

// Test different iterations and memory sizes
fn test_argon2i_parameter_variations() {
	
	password := 'password'.bytes()
	salt := 'somesalt'.bytes()
	
	// Test case: t=1, m=65536, p=1
	expected_hex1 := 'd168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf'
	result1 := hash_i_raw(1, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2i t=1 test should not fail: ${err}'
		return
	}
	
	expected_bytes1 := hex_to_bytes(expected_hex1)
	assert result1 == expected_bytes1, 'Argon2i t=1 test should match expected hash'
	
	// Test case: t=4, m=65536, p=1
	expected_hex2 := 'aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b'
	result2 := hash_i_raw(4, 65536, 1, password, salt, 32) or {
		assert false, 'Argon2i t=4 test should not fail: ${err}'
		return
	}
	
	expected_bytes2 := hex_to_bytes(expected_hex2)
	assert result2 == expected_bytes2, 'Argon2i t=4 test should match expected hash'
	
}

// Test different passwords and salts
fn test_argon2i_input_variations() {
	
	// Test different password
	password1 := 'differentpassword'.bytes()
	salt := 'somesalt'.bytes()
	expected_hex1 := '14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee'
	
	result1 := hash_i_raw(2, 65536, 1, password1, salt, 32) or {
		assert false, 'Argon2i different password test should not fail: ${err}'
		return
	}
	
	expected_bytes1 := hex_to_bytes(expected_hex1)
	assert result1 == expected_bytes1, 'Argon2i different password should match expected hash'
	
	// Test different salt
	password := 'password'.bytes()
	salt2 := 'diffsalt'.bytes()
	expected_hex2 := 'b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271'
	
	result2 := hash_i_raw(2, 65536, 1, password, salt2, 32) or {
		assert false, 'Argon2i different salt test should not fail: ${err}'
		return
	}
	
	expected_bytes2 := hex_to_bytes(expected_hex2)
	assert result2 == expected_bytes2, 'Argon2i different salt should match expected hash'
	
}

// Test comprehensive Argon2i test vectors from reference implementation (version 19)
fn test_argon2i_comprehensive_vectors() {
	
	// Test case 1: Different memory sizes
	result1 := hash_i_raw(2, 262144, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected1 := hex_to_bytes('296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb')
	assert result1 == expected1, 'Argon2i m=262144 test should match'
	
	// Test case 2: Low memory
	result2 := hash_i_raw(2, 256, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected2 := hex_to_bytes('89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f')
	assert result2 == expected2, 'Argon2i m=256 test should match'
	
	// Test case 3: Parallelism = 2
	result3 := hash_i_raw(2, 256, 2, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected3 := hex_to_bytes('4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61')
	assert result3 == expected3, 'Argon2i p=2 test should match'
	
	// Test case 4: High time cost
	result4 := hash_i_raw(4, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected4 := hex_to_bytes('aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b')
	assert result4 == expected4, 'Argon2i t=4 test should match'
	
}

// Test comprehensive Argon2id test vectors from reference implementation 
fn test_argon2id_comprehensive_vectors() {
	
	// Test case 1: Different memory sizes
	result1 := hash_id_raw(2, 262144, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected1 := hex_to_bytes('78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c')
	assert result1 == expected1, 'Argon2id m=262144 test should match'
	
	// Test case 2: Low memory
	result2 := hash_id_raw(2, 256, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected2 := hex_to_bytes('9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe')
	assert result2 == expected2, 'Argon2id m=256 test should match'
	
	// Test case 3: Parallelism = 2
	result3 := hash_id_raw(2, 256, 2, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected3 := hex_to_bytes('6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037')
	assert result3 == expected3, 'Argon2id p=2 test should match'
	
	// Test case 4: Low time cost
	result4 := hash_id_raw(1, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected4 := hex_to_bytes('f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98')
	assert result4 == expected4, 'Argon2id t=1 test should match'
	
	// Test case 5: High time cost
	result5 := hash_id_raw(4, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected5 := hex_to_bytes('9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c')
	assert result5 == expected5, 'Argon2id t=4 test should match'
	
	// Test case 6: Different password
	result6 := hash_id_raw(2, 65536, 1, 'differentpassword'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected6 := hex_to_bytes('0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde')
	assert result6 == expected6, 'Argon2id different password test should match'
	
	// Test case 7: Different salt
	result7 := hash_id_raw(2, 65536, 1, 'password'.bytes(), 'diffsalt'.bytes(), 32) or { panic(err) }
	expected7 := hex_to_bytes('bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c')
	assert result7 == expected7, 'Argon2id different salt test should match'
	
}

// Test PHC string encoding/decoding vectors from reference implementation
fn test_phc_string_vectors() {
	
	// Test Argon2i encoding
	encoded_i := hash_i(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected_i := r'$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA'
	assert encoded_i == expected_i, 'Argon2i PHC encoding should match reference'
	
	// Test Argon2id encoding  
	encoded_id := hash_id(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	expected_id := r'$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc'
	assert encoded_id == expected_id, 'Argon2id PHC encoding should match reference'
	
	// Test verification of correct passwords
	verify_result_i := verify_i(encoded_i, 'password'.bytes()) or { panic(err) }
	assert verify_result_i == true, 'Argon2i verification should succeed'
	
	verify_result_id := verify_id(encoded_id, 'password'.bytes()) or { panic(err) }
	assert verify_result_id == true, 'Argon2id verification should succeed'
	
}

// Test error conditions from reference implementation
fn test_error_conditions() {
	
	// Test salt too short
	result1 := hash_id_raw(2, 65536, 1, 'password'.bytes(), 'short'.bytes(), 32) or {
		// This should fail with salt too short
		assert err.msg().contains('SALT_TOO_SHORT') || err.msg().contains('salt'), 'Should fail with salt too short error'
		return
	}
	assert false, 'Should have failed with salt too short'
	
	// Test memory too little
	result2 := hash_id_raw(2, 1, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or {
		// This should fail with memory too little
		assert err.msg().contains('MEMORY_TOO_LITTLE') || err.msg().contains('memory'), 'Should fail with memory too little error'
		return  
	}
	assert false, 'Should have failed with memory too little'
	
	// Test verification with invalid PHC string (missing $)
	verify_result := verify_i(r'$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA', 'password'.bytes()) or {
		// This should fail with decoding error
		assert err.msg().contains('DECODING_FAIL') || err.msg().contains('decode') || err.msg().contains('parse'), 'Should fail with decoding error'
		return
	}
	assert false, 'Should have failed with decoding error'
	
}

// Test Argon2d functionality (data-dependent variant)
fn test_argon2d_basic_functionality() {
	
	// Basic Argon2d test
	result1 := hash_d_raw(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	assert result1.len == 32, 'Argon2d should produce 32-byte hash'
	
	// Test that Argon2d produces different results than Argon2i and Argon2id for same input
	result_i := hash_i_raw(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	result_id := hash_id_raw(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	
	assert result1 != result_i, 'Argon2d should differ from Argon2i'
	assert result1 != result_id, 'Argon2d should differ from Argon2id'
	assert result_i != result_id, 'Argon2i should differ from Argon2id'
	
	// Test PHC encoding for Argon2d
	encoded := hash_d(2, 65536, 1, 'password'.bytes(), 'somesalt'.bytes(), 32) or { panic(err) }
	assert encoded.starts_with(r'$argon2d$v=19$'), 'Argon2d PHC string should have correct prefix'
	
	// Test verification
	verify_result := verify_d(encoded, 'password'.bytes()) or { panic(err) }
	assert verify_result == true, 'Argon2d verification should succeed'
	
	// Test wrong password verification
	wrong_verify := verify_d(encoded, 'wrongpassword'.bytes()) or { panic(err) }
	assert wrong_verify == false, 'Argon2d wrong password should fail'
	
}