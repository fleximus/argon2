module argon2

// Argon2 parameter limits and constants

// Minimum and maximum number of lanes (degree of parallelism)
pub const min_lanes = u32(1)
pub const max_lanes = u32(0xFFFFFF)

// Minimum and maximum number of threads
pub const min_threads = u32(1)
pub const max_threads = u32(0xFFFFFF)

// Number of synchronization points between lanes per pass
pub const sync_points = u32(4)

// Minimum and maximum digest size in bytes
pub const min_outlen = u32(4)
pub const max_outlen = u32(0xFFFFFFFF)

// Minimum memory blocks (2 blocks per slice)
pub const min_memory = 2 * sync_points

// Maximum memory calculation
pub const max_memory_bits = u32(32) // Simplified for V
pub const max_memory = u32(0xFFFFFFFF)

// Minimum and maximum number of passes
pub const min_time = u32(1)
pub const max_time = u32(0xFFFFFFFF)

// Minimum and maximum password length in bytes
pub const min_pwd_length = u32(0)
pub const max_pwd_length = u32(0xFFFFFFFF)

// Minimum and maximum associated data length in bytes
pub const min_ad_length = u32(0)
pub const max_ad_length = u32(0xFFFFFFFF)

// Minimum and maximum salt length in bytes
pub const min_salt_length = u32(8)
pub const max_salt_length = u32(0xFFFFFFFF)

// Minimum and maximum secret length in bytes
pub const min_secret = u32(0)
pub const max_secret = u32(0xFFFFFFFF)

// Flags for secure wiping
pub const default_flags = u32(0)
pub const flag_clear_password = u32(1) << 0
pub const flag_clear_secret = u32(1) << 1

// Block size in bytes
pub const block_size = u32(1024)

// Number of 64-bit words in a block (1024 bytes / 8 bytes per u64)
pub const addresses_in_block = 128

// Default recommended parameters
pub const default_t_cost = u32(3)      // 3 iterations
pub const default_m_cost = u32(65536)  // 64 MB (2^16 KB)
pub const default_parallelism = u32(4) // 4 lanes/threads
pub const default_hash_len = u32(32)   // 32 bytes output (256 bits)
pub const default_salt_len = u32(16)   // 16 bytes salt (128 bits)