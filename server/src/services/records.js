/**
 * Sealing and opening encrypted records.
 *
 * Every patron record follows the same encrypt-then-MAC pipeline:
 *
 *   ciphertext = ECIES(recipient ECC public key, JSON(record))
 *   tag        = HMAC-SHA256(user MAC key, domain || ciphertext)
 *
 * The domain string is what stops a ciphertext being lifted out of one table
 * and pasted into another: a checkout blob replayed into the reviews table
 * fails its MAC because the tag was computed over a different domain.
 *
 * On read the MAC is checked first. If it fails, decryption is not even
 * attempted - that is the entire point of encrypt-then-MAC, and it is what lets
 * the UI report "tampered" instead of returning attacker-influenced plaintext.
 */
import { eciesEncryptString, eciesDecryptString } from '../crypto/ecc.js'
import { rsaEncryptString, rsaDecryptString } from '../crypto/rsa.js'
import { hmacSha256Hex, verifyHmac } from '../crypto/hmac.js'
import { cbcMacHex, verifyCbcMac } from '../crypto/cbcmac.js'

export const DOMAINS = Object.freeze({
  checkout: 'BookVault-Checkout-v1',
  fine: 'BookVault-Fine-v1',
  review: 'BookVault-Review-v1',
  chat: 'BookVault-Chat-v1',
  profile: 'BookVault-Profile-v1',
})

/** Profile field name -> database column. */
export const PROFILE_FIELDS = Object.freeze({
  email: 'email_enc',
  phone: 'phone_enc',
  libraryCard: 'library_card_enc',
  fullName: 'full_name_enc',
  address: 'address_enc',
})

export const PROFILE_ORDER = Object.freeze(['email', 'phone', 'libraryCard', 'fullName', 'address'])

export function sealEcc(eccPub, macKey, obj, domain) {
  const ciphertext = eciesEncryptString(eccPub, JSON.stringify(obj))
  return { ciphertext, hmac_tag: hmacSha256Hex(macKey, domain + ciphertext) }
}

/**
 * @returns {{ data: object|null, integrity: 'ok'|'tampered'|'undecryptable' }}
 */
export function openEcc(eccPriv, macKey, row, domain) {
  if (!row?.ciphertext || !row?.hmac_tag) return { data: null, integrity: 'tampered' }

  if (!verifyHmac(macKey, domain + row.ciphertext, row.hmac_tag)) {
    return { data: null, integrity: 'tampered' }
  }
  try {
    return { data: JSON.parse(eciesDecryptString(eccPriv, row.ciphertext)), integrity: 'ok' }
  } catch {
    // The tag verified but the payload will not decrypt - most often a record
    // sealed under a key version that has since been rotated away.
    return { data: null, integrity: 'undecryptable' }
  }
}

/**
 * The profile is RSA-encrypted field by field (so a single field can be updated
 * without touching the others) and covered by one CBC-MAC over the whole blob
 * (so a field cannot be deleted or swapped between accounts).
 */
export function profileMacInput(encFields) {
  return DOMAINS.profile + '\n' + PROFILE_ORDER.map(name => encFields[PROFILE_FIELDS[name]] ?? '').join('\n')
}

export function sealProfile(rsaPub, macKey, fields) {
  const encFields = {}
  for (const name of PROFILE_ORDER) {
    const value = fields[name]
    encFields[PROFILE_FIELDS[name]] = value === undefined || value === null ? '' : rsaEncryptString(rsaPub, String(value))
  }
  return { encFields, profile_mac: cbcMacHex(macKey, profileMacInput(encFields)) }
}

export function openProfile(rsaPriv, macKey, userRow) {
  const encFields = {}
  for (const name of PROFILE_ORDER) encFields[PROFILE_FIELDS[name]] = userRow[PROFILE_FIELDS[name]] ?? ''

  const macValid = verifyCbcMac(macKey, profileMacInput(encFields), userRow.profile_mac ?? '')

  const fields = {}
  let decryptable = true
  for (const name of PROFILE_ORDER) {
    const blob = encFields[PROFILE_FIELDS[name]]
    if (!blob) {
      fields[name] = ''
      continue
    }
    try {
      fields[name] = rsaDecryptString(rsaPriv, blob)
    } catch {
      fields[name] = null
      decryptable = false
    }
  }
  return { fields, macValid, decryptable, encFields }
}

/** Re-seals one profile field without disturbing the others. */
export function resealProfile(rsaPub, macKey, currentEncFields, changes) {
  const encFields = { ...currentEncFields }
  for (const [name, value] of Object.entries(changes)) {
    if (!(name in PROFILE_FIELDS)) continue
    encFields[PROFILE_FIELDS[name]] = value === null || value === undefined ? '' : rsaEncryptString(rsaPub, String(value))
  }
  return { encFields, profile_mac: cbcMacHex(macKey, profileMacInput(encFields)) }
}
