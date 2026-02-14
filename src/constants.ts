export const ALGORITHM = 'aes-256-gcm'
export const IV_LENGTH = 12 // 96-bit IV (NIST Recommended for GCM)
export const ENC_KEY_INFO = 'crypthold:v1:enc'

export const DEFAULT_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
export const DEFAULT_LOCK_STALE_MS = 30_000
export const DEFAULT_LOCK_TIMEOUT_MS = 5_000
export const DEFAULT_LOCK_RETRY_INTERVAL_MS = 50
