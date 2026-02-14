import { randomBytes } from 'crypto'
import { describe, expect, it } from 'vitest'
import { Cipher } from '../src/cipher.js'

describe('Cipher', () => {
  const masterKey = randomBytes(32)
  const context = 'test-app'

  describe('HKDF derivation', () => {
    it('should derive deterministic key with same master key and salt', () => {
      const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
      const key1 = Cipher.deriveEncryptionKey(masterKey, salt)
      const key2 = Cipher.deriveEncryptionKey(masterKey, salt)

      expect(key1.equals(key2)).toBe(true)
      expect(key1.length).toBe(32)
    })

    it('should derive different keys for different salts', () => {
      const key1 = Cipher.deriveEncryptionKey(masterKey, Buffer.alloc(16, 1))
      const key2 = Cipher.deriveEncryptionKey(masterKey, Buffer.alloc(16, 2))

      expect(key1.equals(key2)).toBe(false)
    })
  })

  describe('encrypt/decrypt round-trip', () => {
    it('should encrypt and decrypt text correctly', () => {
      const original = 'Hello, Crypthold!'
      const payload = Cipher.encrypt(original, masterKey, context)
      const decrypted = Cipher.decrypt(payload, masterKey, context)

      expect(decrypted).toBe(original)
    })

    it('should encrypt and decrypt JSON correctly', () => {
      const original = JSON.stringify({ apiKey: 'secret123', debug: true })
      const payload = Cipher.encrypt(original, masterKey, context)
      const decrypted = Cipher.decrypt(payload, masterKey, context)

      expect(JSON.parse(decrypted)).toEqual({ apiKey: 'secret123', debug: true })
    })

    it('should generate unique IV for each encryption', () => {
      const text = 'same text'
      const payload1 = Cipher.encrypt(text, masterKey, context)
      const payload2 = Cipher.encrypt(text, masterKey, context)

      expect(payload1.iv).not.toBe(payload2.iv)
      expect(payload1.content).not.toBe(payload2.content)
    })
  })

  describe('AAD context binding', () => {
    it('should throw on context mismatch', () => {
      const payload = Cipher.encrypt('secret', masterKey, 'app-a')

      expect(() => {
        Cipher.decrypt(payload, masterKey, 'app-b')
      }).toThrow('Context Mismatch')
    })

    it('should include context in payload', () => {
      const payload = Cipher.encrypt('data', masterKey, 'my-app')
      expect(payload.aad).toBe('my-app')
    })
  })

  describe('integrity', () => {
    it('should fail on tampered content', () => {
      const payload = Cipher.encrypt('secret', masterKey, context)
      payload.content = 'tampered' + payload.content.slice(8)

      expect(() => {
        Cipher.decrypt(payload, masterKey, context)
      }).toThrow()
    })

    it('should fail on tampered auth tag', () => {
      const payload = Cipher.encrypt('secret', masterKey, context)
      payload.tag = 'a'.repeat(32)

      expect(() => {
        Cipher.decrypt(payload, masterKey, context)
      }).toThrow()
    })

    it('should fail with wrong key', () => {
      const payload = Cipher.encrypt('secret', masterKey, context)
      const wrongKey = randomBytes(32)

      expect(() => {
        Cipher.decrypt(payload, wrongKey, context)
      }).toThrow()
    })
  })
})
