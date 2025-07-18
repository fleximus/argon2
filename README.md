# Argon2 for V

A complete, RFC 9106 compliant implementation of the Argon2 password hashing algorithm in V.

## Features

- ✅ **Complete Implementation**: All three Argon2 variants (Argon2i, Argon2d, Argon2id)
- ✅ **RFC 9106 Compliant**: Matches official test vectors exactly
- ✅ **PHC String Format**: Full support for Password Hashing Competition string format
- ✅ **Security**: Constant-time operations and proper memory management
- ✅ **Performance**: Optimized compression function based on Blake2b
- ✅ **Test-Driven**: Comprehensive test suite with official vectors

## Quick Start

### Simple API (Recommended)

```v
import fleximus.argon2
import crypto.rand

// Generate a secure random salt
salt := rand.bytes(16) or { panic(err) } // 128-bit salt

// Hash with secure defaults (Argon2id, t=3, m=64MB, p=4)
hash := argon2.hash('mypassword'.bytes(), salt) or { panic(err) }
println(hash) // $argon2id$v=19$m=65536,t=3,p=4$...

// Verify password (auto-detects variant)
is_valid := argon2.verify(hash, 'mypassword'.bytes()) or { panic(err) }
if is_valid {
	println('Password verified!')
}
```

### Custom Parameters

```v
import fleximus.argon2

// Hash with custom parameters
hash := argon2.hash_with_params(2, // t_cost: 2 iterations
 32768, // m_cost: 32 MB memory
 2, // parallelism: 2 threads
 'mypassword'.bytes(), // password
 'somesalt'.bytes(), // salt
 32 // hashlen: 32-byte output
 ) or { panic(err) }

// Verify (still auto-detects variant)
is_valid := argon2.verify(hash, 'mypassword'.bytes()) or { panic(err) }
```

## API Reference

### Default Functions (Recommended)

#### Simple Hash Function
```v
import fleximus.argon2

// Hash with secure defaults: Argon2id, t=3, m=64MB, p=4, 128-bit salt, 256-bit output
// The default hash function uses Argon2id for maximum security
password := 'mypassword'.bytes()
salt := 'mysalt123456789'.bytes() // min 8 bytes
hash := argon2.hash(password, salt) or { panic(err) }
```

#### Hash with Custom Parameters  
```v
import fleximus.argon2

// Hash with custom parameters using Argon2id
password := 'mypassword'.bytes()
salt := 'mysalt123456789'.bytes()
hash := argon2.hash_with_params(3, // t_cost: Time cost (iterations)
 65536, // m_cost: Memory cost (KB)
 1, // parallelism: Parallelism degree
 password, // Password bytes
 salt, // Salt bytes (min 8 bytes)
 32 // hashlen: Output hash length
 ) or { panic(err) }
```

#### Universal Verify Function
```v
import fleximus.argon2

// Verify password against any Argon2 PHC string (auto-detects variant)
encoded := r'$argon2id$v=19$m=65536,t=3,p=1$...'
password := 'mypassword'.bytes()
is_valid := argon2.verify(encoded, password) or { panic(err) }
```

### Advanced Hash Functions

#### Argon2id (Recommended)
```v
import fleximus.argon2

// Generate encoded hash
password := 'mypassword'.bytes()
salt := 'mysalt123456789'.bytes()
hash := argon2.hash_id(3, // t_cost: Time cost (iterations)
 65536, // m_cost: Memory cost (KB)
 1, // parallelism: Parallelism degree
 password, // Password bytes
 salt, // Salt bytes (min 8 bytes)
 32 // hashlen: Output hash length
 ) or { panic(err) }

// Generate raw hash
hash_raw := argon2.hash_id_raw(3, // t_cost: Time cost (iterations)
 65536, // m_cost: Memory cost (KB)
 1, // parallelism: Parallelism degree
 password, // Password bytes
 salt, // Salt bytes (min 8 bytes)
 32 // hash_len: Output hash length
 ) or { panic(err) }

// Verify password against encoded hash
encoded := r'$argon2id$v=19$m=65536,t=3,p=1$...'
result := argon2.verify_id(encoded, password) or { panic(err) }
```

#### Argon2i (Data-Independent)
```v
import fleximus.argon2

// For side-channel resistant environments
password := 'mypassword'.bytes()
salt := 'mysalt123456789'.bytes()
encoded := r'$argon2i$v=19$m=65536,t=3,p=1$...'
hash := argon2.hash_i(3, 65536, 1, password, salt, 32) or { panic(err) }
hash_raw := argon2.hash_i_raw(3, 65536, 1, password, salt, 32) or { panic(err) }
result := argon2.verify_i(encoded, password) or { panic(err) }
```

#### Argon2d (Data-Dependent)  
```v
import fleximus.argon2

// For maximum resistance against GPU attacks
password := 'mypassword'.bytes()
salt := 'mysalt123456789'.bytes()
encoded := r'$argon2d$v=19$m=65536,t=3,p=1$...'
hash := argon2.hash_d(3, 65536, 1, password, salt, 32) or { panic(err) }
hash_raw := argon2.hash_d_raw(3, 65536, 1, password, salt, 32) or { panic(err) }
result := argon2.verify_d(encoded, password) or { panic(err) }
```

### Parameter Guidelines

| Use Case | t_cost | m_cost | parallelism |
|----------|--------|---------|-------------|
| **High Security** | 3-4 | 65536-131072 | 1-4 |
| **Interactive** | 2-3 | 32768-65536 | 1-2 |
| **Low Latency** | 1-2 | 16384-32768 | 1 |

### Constants

```v
import fleximus.argon2

// Parameter limits
println('Min output: ${argon2.min_outlen}') // 4 bytes
println('Max output: ${argon2.max_outlen}') // 2^32-1 bytes
println('Min salt: ${argon2.min_salt_length}') // 8 bytes
println('Min memory: ${argon2.min_memory}') // 8 blocks (32 KB)
println('Sync points: ${argon2.sync_points}') // 4 synchronization points

// Recommended defaults
println('Default t_cost: ${argon2.default_t_cost}') // 3 iterations
println('Default m_cost: ${argon2.default_m_cost}') // 65536 KB (64 MB)
println('Default parallelism: ${argon2.default_parallelism}') // 4 threads
println('Default hash len: ${argon2.default_hash_len}') // 32 bytes
```

## Examples

### Password Registration
```v
import fleximus.argon2
import crypto.rand

fn register_user(username string, password string) !string {
	// Generate random salt (128 bits)
	salt := rand.bytes(16) or { return err }

	// Hash password with secure defaults
	hash := argon2.hash(password.bytes(), salt) or { return err }

	// Store username and hash in database
	println('User: ${username}')
	println('Hash: ${hash}')

	return hash
}
```

### Password Authentication
```v
import fleximus.argon2

fn authenticate_user(stored_hash string, password string) !bool {
	// Auto-detects Argon2 variant and verifies
	return argon2.verify(stored_hash, password.bytes())
}

// Usage
hash := r'$argon2id$v=19$m=65536,t=3,p=4$...$...'
is_valid := authenticate_user(hash, 'user_password') or { false }
if is_valid {
	println('Login successful!')
} else {
	println('Invalid password!')
}
```

### Custom Parameters
```v
import fleximus.argon2

fn hash_with_custom_params() !string {
	return argon2.hash_with_params(4, // t_cost: 4 iterations for extra security
	 131072, // m_cost: 128 MB memory usage
	 2, // parallelism: Use 2 threads
	 'secret'.bytes(), // password
	 'unique_salt_16_bytes!'.bytes(), // salt
	 64 // hashlen: 64-byte output
	 )
}
```

### Variant Comparison
```v
import fleximus.argon2

fn compare_variants() {
	password := 'test_password'.bytes()
	salt := 'test_salt_12345'.bytes()

	// Argon2i: Resistant to side-channel attacks
	hash_i := argon2.hash_i_raw(2, 65536, 1, password, salt, 32) or { panic(err) }

	// Argon2d: Maximum resistance to GPU attacks
	hash_d := argon2.hash_d_raw(2, 65536, 1, password, salt, 32) or { panic(err) }

	// Argon2id: Hybrid approach (recommended)
	hash_id := argon2.hash_id_raw(2, 65536, 1, password, salt, 32) or { panic(err) }

	println('Argon2i:  ${hash_i.hex()}')
	println('Argon2d:  ${hash_d.hex()}')
	println('Argon2id: ${hash_id.hex()}')
}
```

## Security Considerations

1. **Use Argon2id** for most applications (hybrid security)
2. **Use Argon2i** in side-channel sensitive environments
3. **Use Argon2d** for maximum GPU resistance (not recommended for most uses)
4. **Generate random salts** (minimum 8 bytes, recommended 16+ bytes)
5. **Adjust parameters** based on your security vs. performance requirements
6. **Use constant-time comparison** when verifying hashes

## Performance

The implementation is optimized for correctness and security. Performance characteristics:

- **Memory**: Configurable from 32 KB to 4 GB
- **CPU**: Scales with t_cost parameter
- **Parallelism**: Supports multi-threading (p > 1)

Benchmark on typical hardware (adjust parameters based on your requirements):
- t=2, m=65536, p=1: ~100ms
- t=3, m=65536, p=1: ~150ms  
- t=2, m=131072, p=1: ~200ms

## Testing

Run the comprehensive test suite:

```bash
v test .
```

The library includes:
- Official RFC 9106 test vectors
- Parameter variation tests
- Input variation tests  
- Error condition tests
- PHC string format tests

## Algorithm Details

This implementation follows RFC 9106 exactly:

1. **Initial Hash (H₀)**: Blake2b of parameters and inputs
2. **Memory Initialization**: Generate first blocks using Blake2b-long
3. **Memory Filling**: 
   - Argon2i: Data-independent addressing with precomputed indices
   - Argon2d: Data-dependent addressing using previous block
   - Argon2id: Hybrid approach combining both methods
4. **Compression**: fBlaMka function with Blake2 rounds
5. **Finalization**: XOR last blocks and Blake2b-long for output

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please ensure:
- All tests pass
- New features include tests
- Code follows V style guidelines
- Security considerations are documented