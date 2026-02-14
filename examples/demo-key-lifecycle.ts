/**
 * Demo: Key lifecycle (multi-key decrypt + rotate)
 * Run with:
 *   npm run build && node --experimental-strip-types examples/demo-key-lifecycle.ts
 */

import * as os from 'os'
import * as path from 'path'
import { Crypthold } from '../dist/index.js'

const appName = 'crypthold-demo-key-lifecycle'
const configPath = path.join(os.tmpdir(), 'crypthold-demo-key-lifecycle', 'store.enc')

async function main() {
  const keyV1 = '1'.repeat(64)
  const keyV2 = '2'.repeat(64)

  process.env.CRYPTHOLD_DEMO_KEY = keyV1
  process.env.CRYPTHOLD_DEMO_KEYS = `v1:${keyV1}`

  const writerV1 = new Crypthold({
    appName,
    configPath,
    encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_KEY',
    encryptionKeySetEnvVar: 'CRYPTHOLD_DEMO_KEYS',
    keyId: 'v1',
  })

  await writerV1.load()
  await writerV1.set('token', 'demo-token-v1')
  console.log('✅ Wrote initial data with keyId=v1')

  process.env.CRYPTHOLD_DEMO_KEY = keyV2
  process.env.CRYPTHOLD_DEMO_KEYS = `v2:${keyV2},v1:${keyV1}`

  const readerWithFallback = new Crypthold({
    appName,
    configPath,
    encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_KEY',
    encryptionKeySetEnvVar: 'CRYPTHOLD_DEMO_KEYS',
    keyId: 'v2',
  })

  await readerWithFallback.load()
  console.log('✅ Loaded old ciphertext using multi-key fallback:', readerWithFallback.get('token'))

  await readerWithFallback.rotate(keyV2)
  console.log('✅ Rotated store to keyId=v2 (atomic re-encrypt)')

  const verifier = new Crypthold({
    appName,
    configPath,
    encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_KEY',
    encryptionKeySetEnvVar: 'CRYPTHOLD_DEMO_KEYS',
    keyId: 'v2',
  })
  await verifier.load()

  console.log('📦 Final state:', verifier.getAll())

  delete process.env.CRYPTHOLD_DEMO_KEY
  delete process.env.CRYPTHOLD_DEMO_KEYS
}

main().catch((error) => {
  console.error('❌ Demo failed:', error)
  process.exit(1)
})
