/**
 * Demo: doctor() + watch() + import/export
 * Run with:
 *   npm run build && node --experimental-strip-types examples/demo-doctor-watch-import-export.ts
 */

import * as os from 'os'
import * as path from 'path'
import { Opal } from '../dist/index.js'

const appName = 'opal-demo-dx-safety'
const baseDir = path.join(os.tmpdir(), 'opal-demo-dx-safety')
const configPath = path.join(baseDir, 'store.enc')
const plainPath = path.join(baseDir, 'backup.json')
const encryptedPath = path.join(baseDir, 'backup.enc')

async function main() {
  process.env.OPAL_DEMO_DX_KEY = 'a'.repeat(64)

  const writer = new Opal({
    appName,
    configPath,
    encryptionKeyEnvVar: 'OPAL_DEMO_DX_KEY',
  })

  await writer.load()
  await writer.set('featureFlags', { darkMode: true, beta: false })

  const report = await writer.doctor()
  console.log('🩺 doctor():', report)

  const watcher = new Opal({
    appName,
    configPath,
    encryptionKeyEnvVar: 'OPAL_DEMO_DX_KEY',
  })
  await watcher.load()

  const stop = watcher.watch(
    (data) => {
      console.log('👀 watch() change event:', data)
    },
    { debounceMs: 50 },
  )

  await writer.set('runtime', { region: 'eu-central-1' })

  await new Promise((resolve) => setTimeout(resolve, 120))
  stop()

  await writer.exportPlain(plainPath)
  await writer.exportEncrypted(encryptedPath)
  console.log('✅ Exported plain + encrypted backups')

  const imported = new Opal({
    appName: `${appName}-imported`,
    configPath: path.join(baseDir, 'imported.enc'),
    encryptionKeyEnvVar: 'OPAL_DEMO_DX_KEY',
  })

  await imported.load()
  await imported.importPlain(plainPath)
  console.log('✅ importPlain() result:', imported.getAll())

  const importedEncrypted = new Opal({
    appName,
    configPath: path.join(baseDir, 'imported-from-encrypted.enc'),
    encryptionKeyEnvVar: 'OPAL_DEMO_DX_KEY',
  })

  await importedEncrypted.load()
  await importedEncrypted.importEncrypted(encryptedPath)
  console.log('✅ importEncrypted() result:', importedEncrypted.getAll())

  delete process.env.OPAL_DEMO_DX_KEY
}

main().catch((error) => {
  console.error('❌ Demo failed:', error)
  process.exit(1)
})
