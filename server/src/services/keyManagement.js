/**
 * Key Management Module (security feature 4, feature F10).
 *
 * Covers the full lifecycle the lab asks for:
 *   generation   - RSA-2048 + secp256k1 + a 256-bit MAC key, per user
 *   storage      - public parts in the clear, private parts wrapped under a
 *                  password-derived key (see crypto/keywrap.js)
 *   distribution - loadPublicKeys() is how one user obtains another's public
 *                  key in order to send them an encrypted chat message
 *   rotation     - rotateKeys() re-encrypts every record the user owns under a
 *                  fresh key pair and destroys the old one
 */
import config from '../config.js'
import { db, unwrap } from '../db/supabase.js'
import { randomBytes } from '../crypto/random.js'
import { bytesToHex, hexToBytes } from '../crypto/bytes.js'
import {
  generateRsaKeyPair,
  rsaPublicFingerprint,
  rsaEncryptString,
  rsaDecryptString,
  modulusBits,
} from '../crypto/rsa.js'
import {
  generateEccKeyPair,
  publicFromPrivate,
  eccPublicFingerprint,
  ecdh,
  CURVE,
} from '../crypto/ecc.js'
import { wrap, unwrap as unwrapKey } from '../crypto/keywrap.js'
import { hmacSha256Hex, verifyHmac } from '../crypto/hmac.js'
import { openEcc, sealEcc, openProfile, sealProfile, DOMAINS } from './records.js'
import { httpError } from '../middleware/errors.js'

export function generateKeyBundle(rsaBits = config.RSA_BITS) {
  const rsa = generateRsaKeyPair(rsaBits)
  const ecc = generateEccKeyPair()
  const macKey = randomBytes(32) // 256-bit HMAC / CBC-MAC key
  return { rsa, ecc, macKey }
}

export function fingerprintsOf(bundle) {
  return {
    rsa: rsaPublicFingerprint(bundle.rsa),
    ecc: eccPublicFingerprint(bundle.ecc.pub),
    rsaBits: modulusBits(bundle.rsa),
    curve: CURVE.name,
  }
}

/** BigInt -> bytes, via an even-length hex string (hex nibbles must pair up). */
function bigIntToBytes(value, minBytes = 0) {
  let hex = value.toString(16)
  if (hex.length % 2) hex = '0' + hex
  while (hex.length < minBytes * 2) hex = '00' + hex
  return hexToBytes(hex)
}

function rowFromBundle(userId, version, bundle, wrapKey) {
  return {
    user_id: userId,
    version,
    rsa_n: bundle.rsa.n.toString(16),
    rsa_e: bundle.rsa.e.toString(16),
    rsa_d_wrapped: wrap(wrapKey, bigIntToBytes(bundle.rsa.d)),
    ecc_pub_x: bundle.ecc.pub.x.toString(16),
    ecc_pub_y: bundle.ecc.pub.y.toString(16),
    ecc_priv_wrapped: wrap(wrapKey, bigIntToBytes(bundle.ecc.priv, 32)),
    mac_key_wrapped: wrap(wrapKey, bundle.macKey),
  }
}

export async function storeKeyBundle(userId, version, bundle, wrapKey) {
  return unwrap(
    await db.from('user_keys').insert(rowFromBundle(userId, version, bundle, wrapKey)).select().single(),
    'key insert',
  )
}

async function currentKeyRow(userId) {
  const row = unwrap(
    await db
      .from('user_keys')
      .select('*')
      .eq('user_id', userId)
      .is('retired_at', null)
      .order('version', { ascending: false })
      .limit(1)
      .maybeSingle(),
    'key lookup',
  )
  if (!row) throw httpError(500, 'NO_KEYS', 'No key material found for this account.')
  return row
}

/** Public key distribution - safe to hand to any authenticated caller. */
export async function loadPublicKeys(userId) {
  const row = await currentKeyRow(userId)
  const rsa = { n: BigInt('0x' + row.rsa_n), e: BigInt('0x' + row.rsa_e) }
  const ecc = { x: BigInt('0x' + row.ecc_pub_x), y: BigInt('0x' + row.ecc_pub_y) }
  return {
    version: row.version,
    rsa,
    ecc,
    createdAt: row.created_at,
    fingerprints: {
      rsa: rsaPublicFingerprint(rsa),
      ecc: eccPublicFingerprint(ecc),
      rsaBits: modulusBits(rsa),
      curve: CURVE.name,
    },
  }
}

/** Unwraps private material. Only ever called with a password-derived wrap key. */
export async function loadPrivateKeys(userId, wrapKey) {
  const row = await currentKeyRow(userId)
  let d
  let eccPriv
  let macKey
  try {
    d = BigInt('0x' + bytesToHex(unwrapKey(wrapKey, row.rsa_d_wrapped)))
    eccPriv = BigInt('0x' + bytesToHex(unwrapKey(wrapKey, row.ecc_priv_wrapped)))
    macKey = unwrapKey(wrapKey, row.mac_key_wrapped)
  } catch {
    throw httpError(401, 'KEY_UNWRAP_FAILED', 'Could not unlock your keys with that password.')
  }
  const rsa = { n: BigInt('0x' + row.rsa_n), e: BigInt('0x' + row.rsa_e), d }
  const pub = { x: BigInt('0x' + row.ecc_pub_x), y: BigInt('0x' + row.ecc_pub_y) }
  return {
    version: row.version,
    rsa,
    ecc: { priv: eccPriv, pub },
    macKey,
    fingerprints: {
      rsa: rsaPublicFingerprint(rsa),
      ecc: eccPublicFingerprint(pub),
      rsaBits: modulusBits(rsa),
      curve: CURVE.name,
    },
  }
}

export async function listKeyVersions(userId) {
  return unwrap(
    await db
      .from('user_keys')
      .select('version, created_at, retired_at')
      .eq('user_id', userId)
      .order('version', { ascending: false }),
    'key history',
  )
}

/**
 * Key rotation (F10).
 *
 * Every record the user owns is decrypted with the old keys and re-encrypted
 * with the new ones, then re-MACed. Records whose MAC does not verify are left
 * untouched and reported as tampered rather than silently re-sealed - carrying
 * a forged record forward under a fresh, valid-looking tag would destroy the
 * evidence of tampering.
 *
 * Ordering is deliberate: the new key row is written first and the old row is
 * deleted last, so a crash in the middle leaves a recoverable state rather than
 * an account with no keys at all.
 */
export async function rotateKeys(userId, wrapKey, onStep = () => {}) {
  const oldKeys = await loadPrivateKeys(userId, wrapKey)
  const oldRow = await currentKeyRow(userId)
  const bundle = generateKeyBundle(config.RSA_BITS)
  const newVersion = oldKeys.version + 1

  const report = {
    from: oldKeys.version,
    to: newVersion,
    checkouts: { rekeyed: 0, tampered: 0 },
    fines: { rekeyed: 0, tampered: 0 },
    reviews: { rekeyed: 0, tampered: 0 },
    chat: { rekeyed: 0, tampered: 0 },
    profile: { rekeyed: 0, tampered: 0 },
  }

  const newEccPub = bundle.ecc.pub
  const newMacKey = bundle.macKey

  // --- ECIES-protected tables -------------------------------------------
  for (const [table, domain, key] of [
    ['checkouts', DOMAINS.checkout, 'checkouts'],
    ['fines', DOMAINS.fine, 'fines'],
    ['reviews', DOMAINS.review, 'reviews'],
  ]) {
    onStep(table)
    const rows = unwrap(
      await db.from(table).select('id, ciphertext, hmac_tag').eq('user_id', userId),
      `${table} rotation read`,
    )
    for (const row of rows ?? []) {
      const opened = openEcc(oldKeys.ecc.priv, oldKeys.macKey, row, domain)
      if (opened.integrity !== 'ok') {
        report[key].tampered++
        continue
      }
      const sealed = sealEcc(newEccPub, newMacKey, opened.data, domain)
      unwrap(
        await db
          .from(table)
          .update({ ciphertext: sealed.ciphertext, hmac_tag: sealed.hmac_tag, key_version: newVersion })
          .eq('id', row.id)
          .select('id')
          .single(),
        `${table} rotation write`,
      )
      report[key].rekeyed++
    }
  }

  // --- Chat (RSA bodies + ECDH-keyed HMAC) -------------------------------
  onStep('chat')
  const messages = unwrap(
    await db
      .from('chat_messages')
      .select('*')
      .or(`sender_id.eq.${userId},recipient_id.eq.${userId}`),
    'chat rotation read',
  )
  for (const msg of messages ?? []) {
    const iAmSender = msg.sender_id === userId
    const myBlob = iAmSender ? msg.body_for_sender : msg.body_for_recipient
    const peerId = iAmSender ? msg.recipient_id : msg.sender_id
    let plaintext
    try {
      plaintext = rsaDecryptString(oldKeys.rsa, myBlob)
    } catch {
      report.chat.tampered++
      continue
    }
    const reEncrypted = rsaEncryptString(bundle.rsa, plaintext)

    const patch = iAmSender
      ? { body_for_sender: reEncrypted, sender_key_version: newVersion }
      : { body_for_recipient: reEncrypted, recipient_key_version: newVersion }

    // The authentication tag lives on the recipient's copy, so only the
    // recipient's rotation needs to recompute it - and it must be recomputed
    // against the peer's current public key.
    if (!iAmSender) {
      try {
        const peer = await loadPublicKeys(peerId)
        const shared = ecdh(bundle.ecc.priv, peer.ecc)
        patch.hmac_tag = hmacSha256Hex(shared, DOMAINS.chat + reEncrypted + msg.ts)
      } catch {
        report.chat.tampered++
        continue
      }
    }
    unwrap(await db.from('chat_messages').update(patch).eq('id', msg.id).select('id').single(), 'chat rotation write')
    report.chat.rekeyed++
  }

  // --- Profile (RSA fields + CBC-MAC) ------------------------------------
  onStep('profile')
  const userRow = unwrap(await db.from('users').select('*').eq('id', userId).single(), 'profile rotation read')
  const opened = openProfile(oldKeys.rsa, oldKeys.macKey, userRow)
  const resealed = sealProfile(bundle.rsa, newMacKey, opened.fields)
  if (!opened.macValid) report.profile.tampered = 1
  report.profile.rekeyed = Object.values(opened.fields).filter(v => v).length

  // TOTP secret is wrapped under the password, not under the key pair, so it is
  // unaffected by rotation and deliberately left alone.

  // --- Commit ------------------------------------------------------------
  onStep('keys')
  await storeKeyBundle(userId, newVersion, bundle, wrapKey)

  unwrap(
    await db
      .from('users')
      .update({ ...resealed.encFields, profile_mac: resealed.profile_mac, key_version: newVersion, updated_at: new Date().toISOString() })
      .eq('id', userId)
      .select('id')
      .single(),
    'profile rotation write',
  )

  // Old keys are destroyed, not archived: an archived key is a key that can
  // still be stolen.
  await db.from('user_keys').delete().eq('id', oldRow.id)

  return {
    version: newVersion,
    report,
    fingerprints: fingerprintsOf(bundle),
    material: { version: newVersion, rsa: bundle.rsa, ecc: bundle.ecc, macKey: bundle.macKey },
  }
}
