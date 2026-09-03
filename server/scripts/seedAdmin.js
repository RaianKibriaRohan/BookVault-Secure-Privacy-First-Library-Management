#!/usr/bin/env node
/**
 * Creates the Head Librarian account.
 *
 *   npm run seed:admin -- --username librarian --password "Vault-Admin-2026"
 *
 * The account is created through exactly the same cryptographic path as a
 * patron registration - salted password hash, RSA-2048 + secp256k1 key pair,
 * wrapped private material, RSA-encrypted profile, CBC-MAC - and then promoted
 * to the admin role. There is deliberately no raw SQL insert here: an account
 * created by hand would have no key material and could never send or read a
 * chat message.
 */
import config from '../src/config.js'
import { db, unwrap } from '../src/db/supabase.js'
import { hashPassword } from '../src/crypto/password.js'
import { deriveWrapKey, wrapString } from '../src/crypto/keywrap.js'
import { generateTotpSecret, totpUri } from '../src/crypto/totp.js'
import { generateKeyBundle, storeKeyBundle, fingerprintsOf } from '../src/services/keyManagement.js'
import { sealProfile } from '../src/services/records.js'

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`)
  if (index !== -1 && process.argv[index + 1]) return process.argv[index + 1]
  return process.env[`ADMIN_${name.toUpperCase()}`] ?? fallback
}

const username = arg('username', 'librarian')
const password = arg('password')
const email = arg('email', 'librarian@bookvault.local')
const phone = arg('phone', '+8801700000000')
const fullName = arg('name', 'Head Librarian')

if (!password || password.length < 8) {
  console.error('\nA password of at least 8 characters is required:\n')
  console.error('  npm run seed:admin -- --username librarian --password "Vault-Admin-2026"\n')
  process.exit(1)
}

const existing = unwrap(await db.from('users').select('id, role').ilike('username', username).maybeSingle(), 'username check')
if (existing) {
  console.error(`\nThe username "${username}" already exists (role: ${existing.role}). Choose another.\n`)
  process.exit(1)
}

console.log(`\nGenerating RSA-${config.RSA_BITS} and secp256k1 key pairs for "${username}"...`)

const { salt, hash } = hashPassword(password, config.PASSWORD_ITERATIONS)
const wrapKey = deriveWrapKey(password, salt, config.KEYWRAP_ITERATIONS)
const bundle = generateKeyBundle(config.RSA_BITS)
const totpSecret = generateTotpSecret()
const { encFields, profile_mac } = sealProfile(bundle.rsa, bundle.macKey, {
  email,
  phone,
  libraryCard: 'STAFF-001',
  fullName,
  address: 'Library administration office',
})

const user = unwrap(
  await db
    .from('users')
    .insert({
      username,
      role: 'admin',
      status: 'active',
      password_salt: salt,
      password_hash: hash,
      totp_secret_wrapped: wrapString(wrapKey, totpSecret),
      ...encFields,
      profile_mac,
      key_version: 1,
    })
    .select()
    .single(),
  'admin insert',
)

await storeKeyBundle(user.id, 1, bundle, wrapKey)

const fingerprints = fingerprintsOf(bundle)

console.log(`
  Head Librarian account created.

    username      ${username}
    role          admin
    RSA-${String(fingerprints.rsaBits).padEnd(9)} ${fingerprints.rsa}
    ${fingerprints.curve.padEnd(14)}${fingerprints.ecc}

  Two-factor secret - shown once, store it now:

    ${totpSecret}

    ${totpUri(totpSecret, username)}

  Add that secret to an authenticator app (or read the code from the
  sign-in screen while ENABLE_LAB_ROUTES=true), then sign in at
  ${config.CLIENT_ORIGIN}/login
`)

process.exit(0)
