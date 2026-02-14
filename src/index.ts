import { AsyncEntry } from '@napi-rs/keyring'
import { randomBytes } from 'crypto'
import * as fs from 'fs/promises'
import * as path from 'path'
import { Cipher } from './cipher.js'
import {
  DEFAULT_LOCK_RETRY_INTERVAL_MS,
  DEFAULT_LOCK_STALE_MS,
  DEFAULT_LOCK_TIMEOUT_MS,
  DEFAULT_MAX_FILE_SIZE_BYTES,
} from './constants.js'
import type {
  EncryptedPayload,
  FileSnapshot,
  KeyCandidate,
  OpalOptions,
  OpalV1File,
} from './types.js'

export class OpalError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message)
    this.name = 'OpalError'
  }
}

export class Opal {
  private filePath: string
  private options: OpalOptions

  // State Guard: null indicates not loaded
  private memoryCache: Record<string, unknown> | null = null
  private fileSnapshot: FileSnapshot | null = null

  constructor(options: OpalOptions) {
    if (!options.appName) {
      throw new Error('Opal: appName is required')
    }

    this.options = options

    const homeDir = process.env.HOME || process.env.USERPROFILE || '.'
    this.filePath =
      options.configPath || path.join(homeDir, '.config', options.appName, 'store.enc')
  }

  /**
   * Initializes a new store. Throws OPAL_ALREADY_INIT if key exists.
   */
  async init(): Promise<void> {
    try {
      await this.getPrimaryKey()
      throw new OpalError('Store already initialized. Use load() instead.', 'OPAL_ALREADY_INIT')
    } catch (e: unknown) {
      if (e instanceof OpalError && e.code === 'OPAL_KEY_NOT_FOUND') {
        const newKey = randomBytes(32).toString('hex')
        const entry = new AsyncEntry(this.options.appName, this.getPrimaryKeyId())
        await entry.setPassword(newKey)
        this.memoryCache = {}
        await this.saveData({})
        return
      }
      throw e
    }
  }

  /**
   * Loads existing store. Throws OPAL_KEY_NOT_FOUND if no key exists.
   */
  async load(): Promise<void> {
    const keyCandidates = await this.getKeyCandidates()

    try {
      await this.assertWithinMaxSize()
      const raw = await fs.readFile(this.filePath, 'utf-8')
      const parsed = JSON.parse(raw) as unknown

      let decryptedJson: string
      let needsMigration = false

      if (this.isV1File(parsed)) {
        decryptedJson = this.decryptV1WithCandidates(parsed, keyCandidates)
      } else {
        const legacyPayload = parsed as EncryptedPayload
        decryptedJson = this.decryptLegacyWithCandidates(legacyPayload, keyCandidates)
        needsMigration = true
      }

      this.memoryCache = JSON.parse(decryptedJson)
      this.fileSnapshot = await this.readFileSnapshot()

      if (needsMigration) {
        await this.saveData(this.memoryCache as Record<string, unknown>)
      }
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        this.memoryCache = {}
        this.fileSnapshot = null
        return
      }

      if (error instanceof OpalError) {
        throw error
      }

      throw new OpalError('Failed to verify encrypted store integrity.', 'OPAL_INTEGRITY_FAIL')
    }
  }

  async rotate(newMasterKey?: Buffer | string): Promise<void> {
    this.ensureLoaded()

    if (newMasterKey !== undefined) {
      await this.persistPrimaryKey(newMasterKey)
    }

    await this.saveData(this.memoryCache!)
  }

  private getPrimaryKeyId(): string {
    return this.options.keyId ?? 'default'
  }

  private normalizeKeyMaterial(input: Buffer | string): Buffer {
    const keyBuffer = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(input, 'hex')

    if (keyBuffer.length !== 32) {
      throw new OpalError(
        'Invalid master key length. Key must be 64 hex characters (32 bytes).',
        'OPAL_INVALID_KEY',
      )
    }

    return keyBuffer
  }

  private normalizeKeyHexOrThrow(keyHex: string): Buffer {
    return this.normalizeKeyMaterial(keyHex)
  }

  private parseEnvKeySet(raw: string): KeyCandidate[] {
    const parsed: KeyCandidate[] = []

    for (const part of raw
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)) {
      const separatorIndex = part.indexOf(':')
      if (separatorIndex <= 0) {
        continue
      }

      const keyId = part.slice(0, separatorIndex).trim()
      const keyHex = part.slice(separatorIndex + 1).trim()

      if (!keyId || !keyHex) {
        continue
      }

      parsed.push({ keyId, key: this.normalizeKeyHexOrThrow(keyHex) })
    }

    return parsed
  }

  private async getPrimaryKey(): Promise<KeyCandidate> {
    const primaryKeyId = this.getPrimaryKeyId()

    if (this.options.encryptionKeyEnvVar && process.env[this.options.encryptionKeyEnvVar]) {
      const keyHex = process.env[this.options.encryptionKeyEnvVar]!
      return { keyId: primaryKeyId, key: this.normalizeKeyHexOrThrow(keyHex) }
    }

    const entry = new AsyncEntry(this.options.appName, primaryKeyId)
    const keyHex = (await entry.getPassword()) ?? null

    if (!keyHex) {
      throw new OpalError(
        `Master key not found for service: ${this.options.appName}. Run 'init()' first.`,
        'OPAL_KEY_NOT_FOUND',
      )
    }

    return { keyId: primaryKeyId, key: this.normalizeKeyHexOrThrow(keyHex) }
  }

  private async getKeyCandidates(): Promise<KeyCandidate[]> {
    const candidates: KeyCandidate[] = []
    const seen = new Set<string>()

    const pushUnique = (candidate: KeyCandidate): void => {
      if (!seen.has(candidate.keyId)) {
        seen.add(candidate.keyId)
        candidates.push(candidate)
      }
    }

    pushUnique(await this.getPrimaryKey())

    if (this.options.encryptionKeySetEnvVar && process.env[this.options.encryptionKeySetEnvVar]) {
      const envSet = this.parseEnvKeySet(process.env[this.options.encryptionKeySetEnvVar]!)
      for (const candidate of envSet) {
        pushUnique(candidate)
      }
    }

    for (const keyId of this.options.keyIds ?? []) {
      if (seen.has(keyId)) {
        continue
      }

      const entry = new AsyncEntry(this.options.appName, keyId)
      const keyHex = (await entry.getPassword()) ?? null
      if (!keyHex) {
        continue
      }

      pushUnique({ keyId, key: this.normalizeKeyHexOrThrow(keyHex) })
    }

    return candidates
  }

  private async persistPrimaryKey(newMasterKey: Buffer | string): Promise<void> {
    const normalized = this.normalizeKeyMaterial(newMasterKey)

    if (this.options.encryptionKeyEnvVar) {
      process.env[this.options.encryptionKeyEnvVar] = normalized.toString('hex')
      return
    }

    const entry = new AsyncEntry(this.options.appName, this.getPrimaryKeyId())
    await entry.setPassword(normalized.toString('hex'))
  }

  // --- Public API ---

  /**
   * Sets a value and persists immediately.
   */
  async set(key: string, value: unknown): Promise<void> {
    this.ensureLoaded()
    this.memoryCache![key] = value
    await this.saveData(this.memoryCache!)
  }

  /**
   * Retrieves a specific value by key.
   */
  get<T>(key: string): T | null {
    this.ensureLoaded()
    if (key in this.memoryCache!) {
      return this.memoryCache![key] as T
    }
    return null
  }

  /**
   * Retrieves all configuration data.
   * Returns a shallow copy to prevent internal cache mutation.
   */
  getAll(): Record<string, unknown> {
    this.ensureLoaded()
    return { ...this.memoryCache! }
  }

  /**
   * Deletes a key and persists immediately.
   */
  async delete(key: string): Promise<void> {
    this.ensureLoaded()
    if (key in this.memoryCache!) {
      delete this.memoryCache![key]
      await this.saveData(this.memoryCache!)
    }
  }

  // --- Helpers ---

  private ensureLoaded(): void {
    if (this.memoryCache === null) {
      throw new OpalError('Store is not loaded. Call await store.load() first.', 'OPAL_NOT_LOADED')
    }
  }

  private decryptWithIntegrityNormalization(payload: EncryptedPayload, key: Buffer): string {
    try {
      return Cipher.decrypt(payload, key, this.options.appName)
    } catch {
      throw new OpalError('Failed to verify encrypted store integrity.', 'OPAL_INTEGRITY_FAIL')
    }
  }

  private decryptV1WithCandidates(file: OpalV1File, candidates: KeyCandidate[]): string {
    const orderedCandidates = [...candidates].sort((a, b) => {
      if (a.keyId === file.header.keyId) return -1
      if (b.keyId === file.header.keyId) return 1
      return 0
    })

    for (const candidate of orderedCandidates) {
      try {
        const encKey = Cipher.deriveEncryptionKey(
          candidate.key,
          Buffer.from(file.header.salt, 'hex'),
        )
        return this.decryptWithIntegrityNormalization(file.payload, encKey)
      } catch (error) {
        if (!(error instanceof OpalError) || error.code !== 'OPAL_INTEGRITY_FAIL') {
          throw error
        }
      }
    }

    throw new OpalError('Failed to verify encrypted store integrity.', 'OPAL_INTEGRITY_FAIL')
  }

  private decryptLegacyWithCandidates(
    payload: EncryptedPayload,
    candidates: KeyCandidate[],
  ): string {
    for (const candidate of candidates) {
      try {
        return this.decryptWithIntegrityNormalization(payload, candidate.key)
      } catch (error) {
        if (!(error instanceof OpalError) || error.code !== 'OPAL_INTEGRITY_FAIL') {
          throw error
        }
      }
    }

    throw new OpalError('Failed to verify encrypted store integrity.', 'OPAL_INTEGRITY_FAIL')
  }

  private async assertWithinMaxSize(): Promise<void> {
    const maxFileSize = this.options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES
    const stat = await fs.stat(this.filePath)

    if (stat.size > maxFileSize) {
      throw new OpalError(
        `Encrypted store exceeds maximum allowed size (${maxFileSize} bytes).`,
        'OPAL_FILE_TOO_LARGE',
      )
    }
  }

  private async readFileSnapshot(): Promise<FileSnapshot | null> {
    try {
      const stat = await fs.stat(this.filePath)
      return { mtimeMs: stat.mtimeMs, size: stat.size }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null
      }
      throw error
    }
  }

  private async assertUnchangedSinceSnapshot(): Promise<void> {
    const current = await this.readFileSnapshot()

    if (this.fileSnapshot === null && current === null) {
      return
    }

    if (this.fileSnapshot === null || current === null) {
      throw new OpalError('Encrypted store changed since last load.', 'OPAL_CONFLICT')
    }

    if (this.fileSnapshot.mtimeMs !== current.mtimeMs || this.fileSnapshot.size !== current.size) {
      throw new OpalError('Encrypted store changed since last load.', 'OPAL_CONFLICT')
    }
  }

  private isV1File(data: unknown): data is OpalV1File {
    if (!data || typeof data !== 'object') {
      return false
    }

    const file = data as Partial<OpalV1File>

    return (
      !!file.header &&
      file.header.v === 1 &&
      file.header.kdf === 'HKDF-SHA256' &&
      typeof file.header.salt === 'string' &&
      typeof file.header.keyId === 'string' &&
      !!file.payload
    )
  }

  private getWritableMode(existingMode?: number): number {
    if (process.platform === 'win32') {
      return 0o600
    }

    if (existingMode === undefined) {
      return 0o600
    }

    return existingMode & 0o600
  }

  private getLockPath(): string {
    return `${this.filePath}.lock`
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms))
  }

  private async readLockMeta(lockPath: string): Promise<{ pid?: number; ts?: number } | null> {
    try {
      const raw = await fs.readFile(lockPath, 'utf-8')
      const parsed = JSON.parse(raw) as { pid?: number; ts?: number }
      return parsed
    } catch {
      return null
    }
  }

  private async acquireLock(): Promise<() => Promise<void>> {
    const lockPath = this.getLockPath()
    const startedAt = Date.now()
    const staleMs = this.options.lockStaleMs ?? DEFAULT_LOCK_STALE_MS
    const timeoutMs = this.options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS
    const retryMs = this.options.lockRetryIntervalMs ?? DEFAULT_LOCK_RETRY_INTERVAL_MS

    while (true) {
      try {
        const handle = await fs.open(lockPath, 'wx', 0o600)
        try {
          await handle.writeFile(JSON.stringify({ pid: process.pid, ts: Date.now() }))
        } finally {
          await handle.close()
        }

        return async () => {
          try {
            await fs.unlink(lockPath)
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
              throw error
            }
          }
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw error
        }

        const meta = await this.readLockMeta(lockPath)
        const lockTs = meta?.ts

        if (typeof lockTs === 'number' && Date.now() - lockTs > staleMs) {
          await fs.unlink(lockPath).catch(() => {})
          continue
        }

        if (Date.now() - startedAt >= timeoutMs) {
          throw new OpalError('Timed out acquiring store lock.', 'OPAL_LOCK_TIMEOUT')
        }

        await this.sleep(retryMs)
      }
    }
  }

  /**
   * Atomic Write Strategy: Write to tmp -> Rename
   * Prevents corruption if process crashes during write.
   */
  /**
   * Atomic Write Strategy: Write to tmp -> Rename
   * Prevents corruption if process crashes during write.
   */
  private async saveData(data: Record<string, unknown>): Promise<void> {
    const releaseLock = await this.acquireLock()

    try {
      const primary = await this.getPrimaryKey()
      await this.assertUnchangedSinceSnapshot()

      const jsonStr = JSON.stringify(data)
      const salt = Cipher.generateSalt()
      const encKey = Cipher.deriveEncryptionKey(primary.key, salt)

      const fileData: OpalV1File = {
        header: {
          v: 1,
          kdf: 'HKDF-SHA256',
          salt: salt.toString('hex'),
          keyId: primary.keyId,
        },
        payload: Cipher.encrypt(jsonStr, encKey, this.options.appName),
      }

      const dir = path.dirname(this.filePath)
      const tempPath = `${this.filePath}.${randomBytes(4).toString('hex')}.tmp`

      await fs.mkdir(dir, { recursive: true })

      let existingMode: number | undefined
      try {
        existingMode = (await fs.stat(this.filePath)).mode
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw error
        }
      }

      try {
        await fs.writeFile(tempPath, JSON.stringify(fileData, null, 2), {
          mode: this.getWritableMode(existingMode),
        })
        await fs.rename(tempPath, this.filePath)
        this.fileSnapshot = await this.readFileSnapshot()
      } catch (error) {
        await fs.unlink(tempPath).catch(() => {})
        throw error
      }
    } finally {
      await releaseLock()
    }
  }
}

// Re-export for convenience
export { Cipher } from './cipher.js'
export type { EncryptedPayload, OpalV1File } from './types.js'
