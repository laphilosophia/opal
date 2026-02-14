import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'crypto'
import { ALGORITHM, ENC_KEY_INFO, IV_LENGTH } from './constants.js'
import type { CipherEncryptOptions, EncryptedPayload } from './types.js'

export class Cipher {
  static deriveEncryptionKey(masterKey: Buffer, salt: Buffer): Buffer {
    return Buffer.from(hkdfSync('sha256', masterKey, salt, Buffer.from(ENC_KEY_INFO, 'utf8'), 32))
  }

  static generateSalt(): Buffer {
    return randomBytes(16)
  }
  /**
   * Encrypts plaintext using AES-256-GCM with AAD context binding.
   */
  static encrypt(
    text: string,
    key: Buffer,
    context: string,
    options?: CipherEncryptOptions,
  ): EncryptedPayload {
    const iv = options?.iv ?? randomBytes(IV_LENGTH)
    const cipher = createCipheriv(ALGORITHM, key, iv)

    // AAD: Context Binding (Prevent Cross-App Replay)
    cipher.setAAD(Buffer.from(context, 'utf8'))

    let encrypted = cipher.update(text, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    return {
      iv: iv.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
      content: encrypted,
      aad: context,
    }
  }

  /**
   * Decrypts payload using AES-256-GCM with AAD verification.
   * Throws if AAD context doesn't match or integrity check fails.
   */
  static decrypt(payload: EncryptedPayload, key: Buffer, expectedContext: string): string {
    if (payload.aad !== expectedContext) {
      throw new Error(
        `Opal: Context Mismatch. Data belongs to '${payload.aad}', expected '${expectedContext}'`,
      )
    }

    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(payload.iv, 'hex'))

    decipher.setAAD(Buffer.from(payload.aad, 'utf8'))
    decipher.setAuthTag(Buffer.from(payload.tag, 'hex'))

    let decrypted = decipher.update(payload.content, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  }
}
