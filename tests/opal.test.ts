import * as fs from 'fs/promises'
import * as os from 'os'
import * as path from 'path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Cipher, Opal, OpalError } from '../src/index.js'

describe('Opal', () => {
  let tempDir: string
  let configPath: string

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'opal-test-'))
    configPath = path.join(tempDir, 'store.enc')
  })

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('lifecycle errors', () => {
    it('should throw OPAL_NOT_LOADED when accessing before load', () => {
      const store = new Opal({
        appName: 'test-app',
        configPath,
        encryptionKeyEnvVar: 'TEST_KEY',
      })

      try {
        store.get('key')
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(OpalError)
        expect((e as OpalError).code).toBe('OPAL_NOT_LOADED')
      }
    })

    it('should throw OPAL_KEY_NOT_FOUND when loading without key', async () => {
      const store = new Opal({
        appName: 'test-app-no-key',
        configPath,
      })

      try {
        await store.load()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(OpalError)
        expect((e as OpalError).code).toBe('OPAL_KEY_NOT_FOUND')
      }
    })
  })

  describe('with env var key', () => {
    const testKey = 'a'.repeat(64) // 32 bytes in hex

    beforeEach(() => {
      process.env.OPAL_TEST_KEY = testKey
    })

    afterEach(() => {
      delete process.env.OPAL_TEST_KEY
    })

    it('should init and load correctly', async () => {
      const store = new Opal({
        appName: 'test-env-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store.load()
      expect(store.getAll()).toEqual({})
    })

    it('should set and get values', async () => {
      const store = new Opal({
        appName: 'test-env-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store.load()
      await store.set('apiKey', 'secret123')
      await store.set('config', { nested: true })

      expect(store.get('apiKey')).toBe('secret123')
      expect(store.get<{ nested: boolean }>('config')).toEqual({ nested: true })
    })

    it('should persist data across instances', async () => {
      const store1 = new Opal({
        appName: 'test-persist',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store1.load()
      await store1.set('token', 'abc123')

      // Create new instance
      const store2 = new Opal({
        appName: 'test-persist',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store2.load()
      expect(store2.get('token')).toBe('abc123')
    })

    it('should delete values', async () => {
      const store = new Opal({
        appName: 'test-delete',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store.load()
      await store.set('temp', 'value')
      expect(store.get('temp')).toBe('value')

      await store.delete('temp')
      expect(store.get('temp')).toBeNull()
    })

    it('should reject invalid key length', async () => {
      process.env.OPAL_BAD_KEY = 'tooshort'

      const store = new Opal({
        appName: 'test-bad-key',
        configPath,
        encryptionKeyEnvVar: 'OPAL_BAD_KEY',
      })

      try {
        await store.load()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(OpalError)
        expect((e as OpalError).code).toBe('OPAL_INVALID_KEY')
      }

      delete process.env.OPAL_BAD_KEY
    })

    it('should migrate legacy payload format to v1 header + payload', async () => {
      const appName = 'legacy-migrate-app'
      const keyBuffer = Buffer.from(testKey, 'hex')
      const legacyPayload = Cipher.encrypt(JSON.stringify({ migrated: true }), keyBuffer, appName)
      await fs.writeFile(configPath, JSON.stringify(legacyPayload))

      const store = new Opal({ appName, configPath, encryptionKeyEnvVar: 'OPAL_TEST_KEY' })
      await store.load()

      expect(store.get('migrated')).toBe(true)

      const migrated = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      expect(migrated.header.v).toBe(1)
      expect(migrated.header.kdf).toBe('HKDF-SHA256')
      expect(typeof migrated.header.salt).toBe('string')
      expect(migrated.payload).toBeDefined()
    })

    it('should normalize tamper errors to OPAL_INTEGRITY_FAIL', async () => {
      const store = new Opal({
        appName: 'tamper-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })
      await store.load()
      await store.set('secret', 'value')

      const json = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      json.payload.tag = '0'.repeat(32)
      await fs.writeFile(configPath, JSON.stringify(json))

      const victim = new Opal({
        appName: 'tamper-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await expect(victim.load()).rejects.toMatchObject({ code: 'OPAL_INTEGRITY_FAIL' })
    })

    it('should enforce max file size guard', async () => {
      const oversized = 'x'.repeat(2048)
      await fs.writeFile(configPath, oversized)

      const store = new Opal({
        appName: 'size-guard-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
        maxFileSizeBytes: 1024,
      })

      await expect(store.load()).rejects.toMatchObject({ code: 'OPAL_FILE_TOO_LARGE' })
    })

    it('should detect optimistic concurrency conflict', async () => {
      const appName = 'optimistic-app'
      const storeA = new Opal({ appName, configPath, encryptionKeyEnvVar: 'OPAL_TEST_KEY' })
      const storeB = new Opal({ appName, configPath, encryptionKeyEnvVar: 'OPAL_TEST_KEY' })

      await storeA.load()
      await storeB.load()

      await storeA.set('a', 1)

      await expect(storeB.set('b', 2)).rejects.toMatchObject({ code: 'OPAL_CONFLICT' })
    })

    it('should wait for lock release and then persist write', async () => {
      const appName = 'parallel-lock-app'
      const store = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
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

      const verifier = new Opal({ appName, configPath, encryptionKeyEnvVar: 'OPAL_TEST_KEY' })
      await verifier.load()
      expect(verifier.get('locked')).toBe(true)
    })

    it('should recover from stale lockfile', async () => {
      const appName = 'stale-lock-app'
      const store = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
        lockStaleMs: 50,
        lockTimeoutMs: 500,
        lockRetryIntervalMs: 20,
      })

      await store.load()

      const staleLockPath = `${configPath}.lock`
      await fs.writeFile(staleLockPath, JSON.stringify({ pid: 999999, ts: Date.now() - 10_000 }))

      await store.set('recovered', 'yes')

      const verifier = new Opal({ appName, configPath, encryptionKeyEnvVar: 'OPAL_TEST_KEY' })
      await verifier.load()
      expect(verifier.get('recovered')).toBe('yes')
    })

    it('should rotate to new keyId without data loss', async () => {
      const appName = 'rotate-app'
      process.env.OPAL_ROTATE_KEY = '1'.repeat(64)
      process.env.OPAL_ROTATE_KEYS = `v1:${process.env.OPAL_ROTATE_KEY}`

      const storeV1 = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_ROTATE_KEY',
        encryptionKeySetEnvVar: 'OPAL_ROTATE_KEYS',
        keyId: 'v1',
      })

      await storeV1.load()
      await storeV1.set('token', 'alpha')

      const rotatedHex = '2'.repeat(64)
      process.env.OPAL_ROTATE_KEYS = `v2:${rotatedHex},v1:${process.env.OPAL_ROTATE_KEY}`

      const storeV2 = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_ROTATE_KEY',
        encryptionKeySetEnvVar: 'OPAL_ROTATE_KEYS',
        keyId: 'v2',
      })

      await storeV2.load()
      await storeV2.rotate(rotatedHex)

      const written = JSON.parse(await fs.readFile(configPath, 'utf-8'))
      expect(written.header.keyId).toBe('v2')

      const verify = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_ROTATE_KEY',
        encryptionKeySetEnvVar: 'OPAL_ROTATE_KEYS',
        keyId: 'v2',
      })

      await verify.load()
      expect(verify.get('token')).toBe('alpha')

      delete process.env.OPAL_ROTATE_KEY
      delete process.env.OPAL_ROTATE_KEYS
    })

    it('should decrypt with old key from key-set when primary key differs', async () => {
      const appName = 'multikey-app'
      const oldKey = '3'.repeat(64)
      const newKey = '4'.repeat(64)

      process.env.OPAL_MULTI_KEY = oldKey
      process.env.OPAL_MULTI_KEYS = `old:${oldKey}`

      const writer = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_MULTI_KEY',
        encryptionKeySetEnvVar: 'OPAL_MULTI_KEYS',
        keyId: 'old',
      })

      await writer.load()
      await writer.set('legacy', true)

      process.env.OPAL_MULTI_KEY = newKey
      process.env.OPAL_MULTI_KEYS = `new:${newKey},old:${oldKey}`

      const reader = new Opal({
        appName,
        configPath,
        encryptionKeyEnvVar: 'OPAL_MULTI_KEY',
        encryptionKeySetEnvVar: 'OPAL_MULTI_KEYS',
        keyId: 'new',
      })

      await reader.load()
      expect(reader.get('legacy')).toBe(true)

      delete process.env.OPAL_MULTI_KEY
      delete process.env.OPAL_MULTI_KEYS
    })

    it('should write store with unix-safe 0600 permissions', async () => {
      const store = new Opal({
        appName: 'perm-app',
        configPath,
        encryptionKeyEnvVar: 'OPAL_TEST_KEY',
      })

      await store.load()
      await store.set('k', 'v')

      if (process.platform === 'win32') {
        return
      }

      const stat = await fs.stat(configPath)
      expect(stat.mode & 0o777).toBe(0o600)
    })
  })
})
