# Opal

Secure, hardened, atomic configuration store for Node.js applications.

[![npm](https://img.shields.io/npm/v/@laphilosophia/opal.svg)](https://www.npmjs.com/package/@laphilosophia/opal)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Opal is a production-grade configuration substrate designed for high-integrity environments. It provides tamper-evident storage, cross-process safety, and seamless key management.

## Features

- **Hardened Security:** AES-256-GCM encryption with HKDF-SHA256 key derivation.
- **Integrity First:** SHA-256 content hashing prevents silent external tampering.
- **Concurrency Safe:** Robust cross-process locking (`.lock`) with automatic stale recovery.
- **Reactive:** Live configuration watching with debounced callbacks.
- **Key Lifecycle:** Native rotation support and multi-key fallback decryption.
- **Production Ready:** Atomic writes, `fsync` support, and comprehensive diagnostic reports.
- **OS Keychain:** Native integration via `@napi-rs/keyring`.

## Installation

```bash
npm install @laphilosophia/opal
```

## Quick Start

```typescript
import { Opal } from '@laphilosophia/opal'

const store = new Opal({ appName: 'my-app' })

// Initialize (once) or Load
await store.load()

// Set and Persist
await store.set('db_password', 'secret123')

// Get with Types
const pass = store.get<string>('db_password')
```

## Advanced Usage

### Reactive Configuration

Watch for external changes (e.g., manual file edits or other processes):

```typescript
store.watch(
  (data) => {
    console.log('Config updated:', data)
  },
  { debounceMs: 50 },
)
```

### Key Rotation

Transition to a new master key without data loss:

```typescript
await store.rotate('new-64-char-hex-key')
```

### Diagnostics (Doctor)

Check the health and integrity of your configuration store:

```typescript
const report = await store.doctor()
// { keyPresent: true, integrityOk: true, permissionsOk: true, lockExists: false ... }
```

### Durability

Ensures data is physically written to disk (useful for high-stakes environments):

```typescript
const store = new Opal({
  appName: 'my-app',
  durability: 'fsync',
})
```

## API Reference

### `new Opal(options)`

| Option                   | Type                  | Description                                              |
| :----------------------- | :-------------------- | :------------------------------------------------------- |
| `appName`                | `string`              | **Required.** Service name for Keychain and AAD context. |
| `configPath`             | `string`              | Custom path for the encrypted store file.                |
| `encryptionKeyEnvVar`    | `string`              | Env var name for the primary master key.                 |
| `encryptionKeySetEnvVar` | `string`              | Env var for multi-key sets (`id1:hex,id2:hex`).          |
| `maxFileSizeBytes`       | `number`              | Limit to prevent memory blow (default: 10MB).            |
| `durability`             | `"normal" \| "fsync"` | Atomic write strategy (default: `"normal"`).             |
| `lockTimeoutMs`          | `number`              | Max wait time for lock acquisition (default: 5s).        |

### Methods

| Method                  | Description                                                   |
| :---------------------- | :------------------------------------------------------------ |
| `init()`                | Generates a new master key in the keychain.                   |
| `load()`                | Loads and decrypts the store. Supports legacy migration.      |
| `get<T>(key)`           | Retrieves a value from memory cache.                          |
| `set(key, value)`       | Updates memory cache and persists atomically.                 |
| `rotate(newKey?)`       | Re-encrypts the entire store with a new key.                  |
| `watch(callback)`       | Starts watching for file changes. Returns `unwatch` function. |
| `doctor()`              | Performs diagnostic checks on keys and file integrity.        |
| `exportEncrypted(path)` | Safely clones the encrypted store.                            |
| `importEncrypted(path)` | Loads an external store into the local substrate.             |

## Error Codes

| Code                  | Description                                                   |
| :-------------------- | :------------------------------------------------------------ |
| `OPAL_INTEGRITY_FAIL` | Decryption or AAD verification failed (Tampering detected).   |
| `OPAL_CONFLICT`       | File changed externally during a write (Hash/mtime mismatch). |
| `OPAL_LOCK_TIMEOUT`   | Failed to acquire process lock within timeout.                |
| `OPAL_FILE_TOO_LARGE` | Store exceeds `maxFileSizeBytes` limit.                       |
| `OPAL_KEY_NOT_FOUND`  | Master key is missing from environment/keychain.              |

## Security

- **Encryption:** AES-256-GCM with 96-bit random IV (NIST SP 800-38D).
- **Key Derivation:** HKDF-SHA256 ensures key separation for every write.
- **Binding:** AAD (Additional Authenticated Data) binds ciphertext to your `appName`.
- **Permissions:** Enforces `0600` (Owner Read/Write) on Unix-like systems.

## License

MIT
