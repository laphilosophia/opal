export interface OpalOptions {
  /** Application name, used for keychain service and AAD context */
  appName: string
  /** Custom path for encrypted config file */
  configPath?: string
  /** Environment variable name containing master key (for CI/CD) */
  encryptionKeyEnvVar?: string
  /** Optional env var containing key set in format `keyId:hex,keyId2:hex` */
  encryptionKeySetEnvVar?: string
  /** Maximum encrypted file size (in bytes) before load aborts */
  maxFileSizeBytes?: number
  /** Key identifier for header metadata */
  keyId?: string
  /** Lock considered stale after this duration in milliseconds */
  lockStaleMs?: number
  /** Maximum wait while trying to acquire lock in milliseconds */
  lockTimeoutMs?: number
  /** Delay between lock retries in milliseconds */
  lockRetryIntervalMs?: number
  /** Optional durability mode for atomic writes */
  durability?: 'normal' | 'fsync'
  /** Additional key IDs to check in keyring for decrypt fallback */
  keyIds?: string[]
  /** Enable deterministic mode for tests */
  deterministicSeed?: number
  /** Override clock source for deterministic tests */
  nowProvider?: () => number
}

export interface DoctorReport {
  keyPresent: boolean
  integrityOk: boolean
  permissionsOk: boolean | null
  lockExists: boolean
  lockStale: boolean
}

export interface WatchOptions {
  debounceMs?: number
}

export interface EncryptedPayload {
  iv: string
  tag: string
  content: string
  aad: string
}

export interface CipherEncryptOptions {
  iv?: Buffer
}

export interface OpalV1Header {
  v: 1
  kdf: 'HKDF-SHA256'
  salt: string
  keyId: string
}

export interface OpalV1File {
  header: OpalV1Header
  payload: EncryptedPayload
}

export interface FileSnapshot {
  mtimeMs: number
  size: number
  contentHash: string
}

export interface KeyCandidate {
  keyId: string
  key: Buffer
}
