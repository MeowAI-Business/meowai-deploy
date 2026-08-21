#!/usr/bin/env node

import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'

const [inputPath, outputPath] = process.argv.slice(2)
if (!inputPath || !outputPath) {
  throw new Error('usage: sign-upgrade-manifest.mjs INPUT OUTPUT')
}

const encodedKey = process.env.MEOWAI_RELEASE_MANIFEST_PRIVATE_KEY?.trim()
if (!encodedKey) {
  throw new Error('MEOWAI_RELEASE_MANIFEST_PRIVATE_KEY is required')
}

const manifest = JSON.parse(await readFile(inputPath, 'utf8'))
if (manifest.signature !== '') {
  throw new Error('unsigned manifest must contain an empty signature')
}

const privateKey = createPrivateKey({
  key: Buffer.from(encodedKey, 'base64'),
  format: 'der',
  type: 'pkcs8',
})
if (privateKey.asymmetricKeyType !== 'ed25519') {
  throw new Error('manifest private key must be Ed25519 PKCS#8 DER')
}

const payload = Buffer.from(JSON.stringify(manifest))
const signature = sign(null, payload, privateKey)
if (!verify(null, payload, createPublicKey(privateKey), signature)) {
  throw new Error('manifest signature self-verification failed')
}

const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
const rawPublicKey = publicDer.subarray(publicDer.length - 32).toString('base64')
const expectedPublicKey = process.env.MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY?.trim()
if (expectedPublicKey && expectedPublicKey !== rawPublicKey) {
  throw new Error('manifest private key does not match configured public key')
}

manifest.signature = signature.toString('base64')
await writeFile(outputPath, JSON.stringify(manifest), { mode: 0o600 })
process.stdout.write(`manifest signed; public_key=${rawPublicKey}\n`)
