# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-02-14

### Fixed

- **Security**: Prevented deterministicSeed outside test environment.

## [2.2.0] - 2026-02-14

### Added

- **Memory Security**: New `destroy()` method to manually clear sensitive material and cache from memory.

### Changed

- **Performance Optimization**: Fixed a double-read bug in the `load()` sequence, reducing I/O latency.
- **I/O Efficiency**: Optimized snapshot validation to check file metadata before performing a full SHA-256 hash.
- **Write Optimization**: Prevented redundant disk I/O in the `set()` operation when the input value is identical to the cached one.
- **Refactoring**: Decoupled lock management logic into a dedicated `LockManager` class and moved errors to `error.ts`.

## [2.1.0] - 2026-02-14

### Added

- **Examples**: Added examples for all API methods.
- **CI**: Added GitHub Actions for automated testing and publishing.

## [2.0.0] - 2026-02-14

### Added

- **Hardened Optimistic Concurrency**: Stricter conflict detection using SHA-256 content hashing in addition to file metadata.
- **Reactive Watch API**: New `watch()` method for live, event-driven configuration updates.
- **Doctor Diagnostic tool**: New `doctor()` API providing a comprehensive report on key presence, integrity, permissions, and lock status.
- **Data Mobility**: Robust `import` and `export` utilities for both encrypted and plain JSON data with built-in size guards.
- **Improved Durability**: Optional `durability: "fsync"` mode for high-integrity atomic writes.
- **Testing Reliability**: Native support for deterministic seed mode and custom clock providers for repeatable test scenarios.
- **Resilience**: Integrated automatic conflict retry logic (one-phase) for high-concurrency environments.

### Changed

- Transitioned to "Hardened" core architecture.
- Improved error messaging for conflict and size violations.

## [1.2.0] - 2026-02-14

### Added

- **Cross-process Locking**: Implemented a robust lockfile mechanism (`.lock`) to prevent concurrent write collisions between multiple processes.
- **Lock Recovery**: Automatic detection and recovery from stale lockfiles (default 30s stale threshold).
- **Key Rotation**: New `rotate(newMasterKey)` method allowing seamless transition to new master keys without data loss.
- **Multi-key Decryption**: Support for multiple decryption keys via environmental key-sets (`encryptionKeySetEnvVar`) and multiple keyring `keyIds` for graceful key migration.
- **Improved Configurability**: New options for tuning lock behavior (`lockStaleMs`, `lockTimeoutMs`, `lockRetryIntervalMs`).
- **Architectural Refactoring**: Centralized constants and types into dedicated modules (`src/constants.ts`, `src/types.ts`) for better maintainability.

### Changed

- Refactored `Crypthold` and `Cipher` classes to use centralized constants and improved type safety.
- Expanded `CryptholdOptions` with multi-key and locking configuration.

### Removed

- Deleted `src/cipher.types.ts` in favor of a unified `src/types.ts`.

## [1.1.0] - 2026-02-14

### Added

- HKDF-SHA256 key derivation for enhanced security (master keys are now used to derive unique encryption keys)
- File Format V1: Structured JSON format with metadata header (`v`, `kdf`, `salt`, `keyId`)
- Atomic write strategy using temporary files to prevent data corruption during crashes
- Automatic migration support from v1.0.0 legacy format
- Optimistic concurrency control using file snapshotting (`mtime` and `size` checks)
- File size guard (default 10MB) to prevent loading oversized files
- Unix-specific file mode enforcement (0600) for stored configuration

### Changed

- Normalized error codes for robust programmatic handling (e.g., `CRYPTHOLD_INTEGRITY_FAIL`, `CRYPTHOLD_CONFLICT`, `CRYPTHOLD_FILE_TOO_LARGE`)

## [1.0.0] - 2026-01-14

### Added

- Initial release
- AES-256-GCM encryption with 96-bit IV (NIST compliant)
- OS Keychain integration via `@napi-rs/keyring`
- Environment variable key support for CI/CD
- Atomic write strategy (temp file + rename)
- AAD context binding to prevent cross-app replay
- Full API: `init()`, `load()`, `get()`, `getAll()`, `set()`, `delete()`
- TypeScript support with ESM/CJS dual build
