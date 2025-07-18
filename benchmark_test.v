module argon2

import time

fn test_performance_benchmarks() {
	password := 'benchmark_password'.bytes()
	salt := 'benchmark_salt_16'.bytes()
	
	
	// Benchmark 1: Low security parameters
	start1 := time.now()
	_ := hash_id_raw(1, 16384, 1, password, salt, 32) or { panic(err) }
	duration1 := time.since(start1)
	
	// Benchmark 2: Medium security parameters
	start2 := time.now()
	_ := hash_id_raw(2, 65536, 1, password, salt, 32) or { panic(err) }
	duration2 := time.since(start2)
	
	// Benchmark 3: High security parameters  
	start3 := time.now()
	_ := hash_id_raw(3, 131072, 1, password, salt, 32) or { panic(err) }
	duration3 := time.since(start3)
	
	// Benchmark 4: Variant comparison
	
	start_i := time.now()
	_ := hash_i_raw(2, 65536, 1, password, salt, 32) or { panic(err) }
	duration_i := time.since(start_i)
	
	start_id := time.now()
	_ := hash_id_raw(2, 65536, 1, password, salt, 32) or { panic(err) }
	duration_id := time.since(start_id)
	
}