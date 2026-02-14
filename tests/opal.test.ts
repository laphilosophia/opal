import * as fs from 'fs/promises'
import * as os from 'os'
import * as path from 'path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Cipher, Crypthold, CryptholdError } from '../src/index.js'

describe('Crypthold', () => {
  let tempDir: string
  let configPath: string

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'crypthold-test-'))
    configPath = path.join(tempDir, 'store.enc')
  })

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('lifecycle errors', () => {
    it('should throw CRYPTHOLD_NOT_LOADED when accessing before load', () => {
      const store = new Crypthold({
        appName: 'test-app',
        configPath,
        encryptionKeyEnvVar: 'TEST_KEY',
      })

      try {
        store.get('key')
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(CryptholdError)
        expect((e as CryptholdError).code).toBe('CRYPTHOLD_NOT_LOADED')
      }
    })

    it('should throw CRYPTHOLD_KEY_NOT_FOUND when loading without key', async () => {
      const store = new Crypthold({
        appName: 'test-app-no-key',
        configPath,
      })

      try {
        await store.load()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(CryptholdError)
        expect((e as CryptholdError).code).toBe('CRYPTHOLD_KEY_NOT_FOUND')
      }
    })
  })

  describe('with env var key', () => {
    const testKey = 'a'.repeat(64) // 32 bytes in hex

    beforeEach(() => {
      process.env.CRYPTHOLD_TEST_KEY = testKey
    })

    afterEach(() => {
      delete process.env.CRYPTHOLD_TEST_KEY
    })

    it('should init and load correctly', async () => {
      const store = new Crypthold({
        appName: 'test-env-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      expect(store.getAll()).toEqual({})
    })

    it('should set and get values', async () => {
      const store = new Crypthold({
        appName: 'test-env-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('apiKey', 'secret123')
      await store.set('config', { nested: true })

      expect(store.get('apiKey')).toBe('secret123')
      expect(store.get<{ nested: boolean }>('config')).toEqual({ nested: true })
    })

    it('should persist data across instances', async () => {
      const store1 = new Crypthold({
        appName: 'test-persist',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store1.load()
      await store1.set('token', 'abc123')

      // Create new instance
      const store2 = new Crypthold({
        appName: 'test-persist',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store2.load()
      expect(store2.get('token')).toBe('abc123')
    })

    it('should delete values', async () => {
      const store = new Crypthold({
        appName: 'test-delete',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('temp', 'value')
      expect(store.get('temp')).toBe('value')

      await store.delete('temp')
      expect(store.get('temp')).toBeNull()
    })

    it('should reject invalid key length', async () => {
      process.env.CRYPTHOLD_BAD_KEY = 'tooshort'

      const store = new Crypthold({
        appName: 'test-bad-key',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_BAD_KEY',
      })

      try {
        await store.load()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(CryptholdError)
        expect((e as CryptholdError).code).toBe('CRYPTHOLD_INVALID_KEY')
      }

      delete process.env.CRYPTHOLD_BAD_KEY
    })

    it('should migrate legacy payload format to v1 header + payload', async () => {
      const appName = 'legacy-migrate-app'
      const keyBuffer = Buffer.from(testKey, 'hex')
      const legacyPayload = Cipher.encrypt(JSON.stringify({ migrated: true }), keyBuffer, appName)
      await fs.writeFile(configPath, JSON.stringify(legacyPayload))

      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await store.load()

      expect(store.get('migrated')).toBe(true)

      const migrated = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      expect(migrated.header.v).toBe(1)
      expect(migrated.header.kdf).toBe('HKDF-SHA256')
      expect(typeof migrated.header.salt).toBe('string')
      expect(migrated.payload).toBeDefined()
    })

    it('should normalize tamper errors to CRYPTHOLD_INTEGRITY_FAIL', async () => {
      const store = new Crypthold({
        appName: 'tamper-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await store.load()
      await store.set('secret', 'value')

      const json = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      json.payload.tag = '0'.repeat(32)
      await fs.writeFile(configPath, JSON.stringify(json))

      const victim = new Crypthold({
        appName: 'tamper-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await expect(victim.load()).rejects.toMatchObject({ code: 'CRYPTHOLD_INTEGRITY_FAIL' })
    })

    it('should enforce max file size guard', async () => {
      const oversized = 'x'.repeat(2048)
      await fs.writeFile(configPath, oversized)

      const store = new Crypthold({
        appName: 'size-guard-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
        maxFileSizeBytes: 1024,
      })

      await expect(store.load()).rejects.toMatchObject({ code: 'CRYPTHOLD_FILE_TOO_LARGE' })
    })

    it('should detect optimistic concurrency conflict', async () => {
      const appName = 'optimistic-app'
      const storeA = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      const storeB = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await storeA.load()
      await storeB.load()

      await storeA.set('a', 1)

      await expect(storeB.set('b', 2)).rejects.toMatchObject({ code: 'CRYPTHOLD_CONFLICT' })
    })

    it('should wait for lock release and then persist write', async () => {
      const appName = 'parallel-lock-app'
      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
        lockTimeoutMs: 2_000,
        lockRetryIntervalMs: 25,
      })

      await store.load()

      const lockPath = `${configPath}.lock`
      await fs.writeFile(lockPath, JSON.stringify({ pid: process.pid, ts: Date.now() }))

      const releasePromise = (async () => {
        await new Promise((resolve) => setTimeout(resolve, 250))
        await fs.unlink(lockPath)
      })()

      await store.set('locked', true)
      await releasePromise

      const verifier = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await verifier.load()
      expect(verifier.get('locked')).toBe(true)
    })

    it('should recover from stale lockfile', async () => {
      const appName = 'stale-lock-app'
      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
        lockStaleMs: 50,
        lockTimeoutMs: 500,
        lockRetryIntervalMs: 20,
      })

      await store.load()

      const staleLockPath = `${configPath}.lock`
      await fs.writeFile(staleLockPath, JSON.stringify({ pid: 999999, ts: Date.now() - 10_000 }))

      await store.set('recovered', 'yes')

      const verifier = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await verifier.load()
      expect(verifier.get('recovered')).toBe('yes')
    })

    it('should rotate to new keyId without data loss', async () => {
      const appName = 'rotate-app'
      process.env.CRYPTHOLD_ROTATE_KEY = '1'.repeat(64)
      process.env.CRYPTHOLD_ROTATE_KEYS = `v1:${process.env.CRYPTHOLD_ROTATE_KEY}`

      const storeV1 = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_ROTATE_KEY',
        encryptionKeySetEnvVar: 'CRYPTHOLD_ROTATE_KEYS',
        keyId: 'v1',
      })

      await storeV1.load()
      await storeV1.set('token', 'alpha')

      const rotatedHex = '2'.repeat(64)
      process.env.CRYPTHOLD_ROTATE_KEYS = `v2:${rotatedHex},v1:${process.env.CRYPTHOLD_ROTATE_KEY}`

      const storeV2 = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_ROTATE_KEY',
        encryptionKeySetEnvVar: 'CRYPTHOLD_ROTATE_KEYS',
        keyId: 'v2',
      })

      await storeV2.load()
      await storeV2.rotate(rotatedHex)

      const written = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      expect(written.header.keyId).toBe('v2')

      const verify = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_ROTATE_KEY',
        encryptionKeySetEnvVar: 'CRYPTHOLD_ROTATE_KEYS',
        keyId: 'v2',
      })

      await verify.load()
      expect(verify.get('token')).toBe('alpha')

      delete process.env.CRYPTHOLD_ROTATE_KEY
      delete process.env.CRYPTHOLD_ROTATE_KEYS
    })

    it('should decrypt with old key from key-set when primary key differs', async () => {
      const appName = 'multikey-app'
      const oldKey = '3'.repeat(64)
      const newKey = '4'.repeat(64)

      process.env.CRYPTHOLD_MULTI_KEY = oldKey
      process.env.CRYPTHOLD_MULTI_KEYS = `old:${oldKey}`

      const writer = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_MULTI_KEY',
        encryptionKeySetEnvVar: 'CRYPTHOLD_MULTI_KEYS',
        keyId: 'old',
      })

      await writer.load()
      await writer.set('legacy', true)

      process.env.CRYPTHOLD_MULTI_KEY = newKey
      process.env.CRYPTHOLD_MULTI_KEYS = `new:${newKey},old:${oldKey}`

      const reader = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_MULTI_KEY',
        encryptionKeySetEnvVar: 'CRYPTHOLD_MULTI_KEYS',
        keyId: 'new',
      })

      await reader.load()
      expect(reader.get('legacy')).toBe(true)

      delete process.env.CRYPTHOLD_MULTI_KEY
      delete process.env.CRYPTHOLD_MULTI_KEYS
    })

    it('should detect external change using content hash even when mtime is restored', async () => {
      const appName = 'hash-conflict-app'
      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('base', true)

      const before = await fs.stat(configPath)
      const raw = await fs.readFile(configPath, 'utf-8')
      const pivot = Math.max(1, Math.floor(raw.length / 2))
      const replacement = raw[pivot] === 'a' ? 'b' : 'a'
      const tampered = `${raw.slice(0, pivot)}${replacement}${raw.slice(pivot + 1)}`

      await fs.writeFile(configPath, tampered)
      await fs.utimes(configPath, before.atime, before.mtime)

      await expect(store.set('afterTamper', true)).rejects.toMatchObject({
        code: 'CRYPTHOLD_CONFLICT',
      })
    })

    it('should retry once and then abort on persistent conflict', async () => {
      const appName = 'retry-conflict-app'
      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('base', 1)

      const originalRead = (store as any).readFileSnapshot.bind(store)
      let calls = 0
      ;(store as any).readFileSnapshot = async () => {
        calls += 1
        const snapshot = await originalRead()
        if (!snapshot) {
          return snapshot
        }

        return { ...snapshot, contentHash: `${snapshot.contentHash}-conflict` }
      }

      await expect(store.set('next', 2)).rejects.toMatchObject({ code: 'CRYPTHOLD_CONFLICT' })
      expect(calls).toBeGreaterThanOrEqual(2)
    })

    it('should provide doctor report with key and integrity status', async () => {
      const appName = 'doctor-app'
      const store = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('ok', true)

      const report = await store.doctor()
      expect(report.keyPresent).toBe(true)
      expect(report.integrityOk).toBe(true)
      expect(report.lockStale).toBe(false)
    })

    it('should support encrypted export/import with size guard', async () => {
      const appName = 'import-export-app'
      const source = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await source.load()
      await source.set('secret', 'value')

      const encryptedPath = path.join(tempDir, 'backup.enc')
      await source.exportEncrypted(encryptedPath)

      const targetPath = path.join(tempDir, 'target.enc')
      const target = new Crypthold({
        appName,
        configPath: targetPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      await target.load()
      await target.importEncrypted(encryptedPath)
      expect(target.get('secret')).toBe('value')

      const tooLargePath = path.join(tempDir, 'too-large.enc')
      await fs.writeFile(tooLargePath, 'x'.repeat(4096))
      const limited = new Crypthold({
        appName,
        configPath: targetPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
        maxFileSizeBytes: 128,
      })
      await expect(limited.importEncrypted(tooLargePath)).rejects.toMatchObject({
        code: 'CRYPTHOLD_FILE_TOO_LARGE',
      })
    })

    it('should notify watch subscribers on external change', async () => {
      const appName = 'watch-app'
      const writer = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })
      const watcherStore = new Crypthold({
        appName,
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await writer.load()
      await watcherStore.load()

      const changed = new Promise<Record<string, unknown>>((resolve) => {
        const stop = watcherStore.watch(
          (data) => {
            stop()
            resolve(data)
          },
          { debounceMs: 20 },
        )
      })

      await writer.set('k', 'v')
      const data = await changed
      expect(data.k).toBe('v')
    })

    it('should generate deterministic ciphertext with seeded mode and fake clock', async () => {
      const appName = 'deterministic-app'
      const baseNow = 1700000000000
      const makeStore = (cfg: string) =>
        new Crypthold({
          appName,
          configPath: cfg,
          encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
          deterministicSeed: 42,
          nowProvider: () => baseNow,
        })

      const configPathA = path.join(tempDir, 'det-a.enc')
      const configPathB = path.join(tempDir, 'det-b.enc')

      const storeA = makeStore(configPathA)
      await storeA.load()
      await storeA.set('same', 'data')

      const storeB = makeStore(configPathB)
      await storeB.load()
      await storeB.set('same', 'data')

      const fileA = await fs.readFile(configPathA, 'utf-8')
      const fileB = await fs.readFile(configPathB, 'utf-8')
      expect(fileA).toBe(fileB)
    })

    it('should write store with unix-safe 0600 permissions', async () => {
      const store = new Crypthold({
        appName: 'perm-app',
        configPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('k', 'v')

      if (process.platform === 'win32') {
        return
      }

      const stat = await fs.stat(configPath)
      expect(stat.mode & 0o777).toBe(0o600)
    })

    it('should create missing parent directory before lock acquisition', async () => {
      const nestedPath = path.join(tempDir, 'missing', 'nested', 'store.enc')

      const store = new Crypthold({
        appName: 'lock-dir-create',
        configPath: nestedPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await store.load()
      await store.set('ok', true)

      const persisted = new Crypthold({
        appName: 'lock-dir-create',
        configPath: nestedPath,
        encryptionKeyEnvVar: 'CRYPTHOLD_TEST_KEY',
      })

      await persisted.load()
      expect(persisted.get('ok')).toBe(true)
    })
  })
})
