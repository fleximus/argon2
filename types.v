module argon2

// Argon2 variants
pub enum Argon2Type {
	argon2_d = 0   // Data-dependent memory access
	argon2_i = 1   // Data-independent memory access  
	argon2_id = 2  // Hybrid of argon2_i and argon2_d
}

// Argon2 version numbers
@[_allow_multiple_values]
pub enum Argon2Version {
	version_10 = 0x10
	version_13 = 0x13
	version_number = 0x13  // Current version
}

// Argon2 error codes
pub enum Argon2ErrorCode {
	ok = 0
	output_ptr_null = -1
	output_too_short = -2
	output_too_long = -3
	pwd_too_short = -4
	pwd_too_long = -5
	salt_too_short = -6
	salt_too_long = -7
	ad_too_short = -8
	ad_too_long = -9
	secret_too_short = -10
	secret_too_long = -11
	time_too_small = -12
	time_too_large = -13
	memory_too_little = -14
	memory_too_much = -15
	lanes_too_few = -16
	lanes_too_many = -17
	pwd_ptr_mismatch = -18
	salt_ptr_mismatch = -19
	secret_ptr_mismatch = -20
	ad_ptr_mismatch = -21
	memory_allocation_error = -22
	free_memory_cbk_null = -23
	allocate_memory_cbk_null = -24
	incorrect_parameter = -25
	incorrect_type = -26
	out_ptr_mismatch = -27
	threads_too_few = -28
	threads_too_many = -29
	missing_args = -30
	encoding_fail = -31
	decoding_fail = -32
	thread_fail = -33
	decoding_length_fail = -34
	verify_mismatch = -35
}

// Main Argon2 context structure
pub struct Argon2Context {
pub mut:
	out     []u8    // Output array
	outlen  u32     // Digest length
	pwd     []u8    // Password array
	pwdlen  u32     // Password length
	salt    []u8    // Salt array  
	saltlen u32     // Salt length
	secret  []u8    // Key array (optional)
	secretlen u32   // Key length
	ad      []u8    // Associated data array (optional)
	adlen   u32     // Associated data length
	t_cost  u32     // Number of passes
	m_cost  u32     // Amount of memory requested (KB)
	lanes   u32     // Number of lanes
	threads u32     // Maximum number of threads
	version u32     // Version number
	flags   u32     // Configuration flags
}

// Internal processing state will be defined in core.v

// Hash result structure
pub struct Argon2Result {
pub:
	hash []u8
	encoded string
	error Argon2ErrorCode
}