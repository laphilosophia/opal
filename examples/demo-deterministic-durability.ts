/**
 * Demo: deterministic mode + fsync durability + conflict behavior
 * Run with:
 *   npm run build && node --experimental-strip-types examples/demo-deterministic-durability.ts
 */

import * as fs from 'fs/promises'
import * as os from 'os'
import * as path from 'path'
import { Crypthold, CryptholdError } from '../dist/index.js'

const appName = 'crypthold-demo-deterministic'
const baseDir = path.join(os.tmpdir(), 'crypthold-demo-deterministic')

async function main() {
  process.env.CRYPTHOLD_DEMO_DET_KEY = 'b'.repeat(64)

  const now = 1_700_000_000_000

  const makeStore = (configPath: string) =>
    new Crypthold({
      appName,
      configPath,
      encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_DET_KEY',
      durability: 'fsync',
      deterministicSeed: 42,
      nowProvider: () => now,
    })

  const pathA = path.join(baseDir, 'a.enc')
  const pathB = path.join(baseDir, 'b.enc')

  const storeA = makeStore(pathA)
  await storeA.load()
  await storeA.set('same', 'payload')

  const storeB = makeStore(pathB)
  await storeB.load()
  await storeB.set('same', 'payload')

  const textA = await fs.readFile(pathA, 'utf-8')
  const textB = await fs.readFile(pathB, 'utf-8')

  console.log('🎯 Deterministic ciphertext equal:', textA === textB)

  const conflictPath = path.join(baseDir, 'conflict.enc')
  const s1 = new Crypthold({
    appName,
    configPath: conflictPath,
    encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_DET_KEY',
  })
  const s2 = new Crypthold({
    appName,
    configPath: conflictPath,
    encryptionKeyEnvVar: 'CRYPTHOLD_DEMO_DET_KEY',
  })

  await s1.load()
  await s2.load()

  await s1.set('writer', 'first')

  try {
    await s2.set('writer', 'second')
  } catch (error) {
    if (error instanceof CryptholdError && error.code === 'CRYPTHOLD_CONFLICT') {
      console.log('✅ Conflict detected as expected (CRYPTHOLD_CONFLICT)')
    } else {
      throw error
    }
  }

  delete process.env.CRYPTHOLD_DEMO_DET_KEY
}

main().catch((error) => {
  console.error('❌ Demo failed:', error)
  process.exit(1)
})
