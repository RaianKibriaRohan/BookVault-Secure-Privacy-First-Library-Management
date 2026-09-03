/**
 * Password-derived protection for PRIVATE KEY MATERIAL.
 *
 * Read this before judging it against the "asymmetric only" rule: user records
 * are never protected by this module. Checkouts, reviews, fines, chat bodies
 * and profile fields are always RSA- or ECIES-encrypted. What lives here is the
 * key-at-rest problem - if the server simply stored RSA/ECC private keys in the
 * database, then anyone with database access (including the Head Librarian)
 * could decrypt every patron record, and the whole privacy claim would be
 * theatre.
 *
 * So private keys and the TOTP secret are wrapped under a value derived from
 * the patron's password, which the server only ever sees for the instant it
 * takes to authenticate. A database dump yields wrapped blobs and nothing else.
 *
 * deriveWrapKey is a hand-rolled iterated-hash KDF standing in for PBKDF2,
 * which lives in node:crypto and is therefore off-limits.
 */
import { sha256 } from './sha256.js'
import { hmacSha256 } from './hmac.js'
import { keystream } from './kdf.js'
import { randomBytes } from './random.js'
import {
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
  concatBytes,
  timingSafeEqual,
} from './bytes.js'

const NONCE_LEN = 16
const TAG_LEN = 32
const WRAP_INFO = 'BookVault-KeyWrap-v1'

/**
 * key_0     = SHA-256(salt || password || 'BookVault-WrapKey')
 * key_{i+1} = SHA-256(key_i || salt || be32(i))
 *
 * The iteration count is the work factor: raising it makes an offline
 * dictionary attack against a stolen database proportionally more expensive.
 */
export function deriveWrapKey(password, saltHex, iterations = 120000) {
  const salt = typeof saltHex === 'string' ? hexToBytes(saltHex) : saltHex
  let acc = sha256(concatBytes(salt, utf8ToBytes(String(password)), utf8ToBytes('BookVault-WrapKey')))
  const counter = new Uint8Array(4)
  for (let i = 0; i < iterations; i++) {
    counter[0] = (i >>> 24) & 0xff
    counter[1] = (i >>> 16) & 0xff
    counter[2] = (i >>> 8) & 0xff
    counter[3] = i & 0xff
    acc = sha256(concatBytes(acc, salt, counter))
  }
  return acc
}

/** Blob layout: nonce(16) || ciphertext(n) || tag(32), hex encoded. */
export function wrap(wrapKey, plaintextBytes) {
  const pt = plaintextBytes instanceof Uint8Array ? plaintextBytes : utf8ToBytes(String(plaintextBytes))
  const nonce = randomBytes(NONCE_LEN)
  const stream = keystream(concatBytes(wrapKey, nonce), WRAP_INFO, pt.length)
  const ct = new Uint8Array(pt.length)
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ stream[i]
  const tag = hmacSha256(wrapKey, concatBytes(nonce, ct))
  return bytesToHex(concatBytes(nonce, ct, tag))
}

export function unwrap(wrapKey, blob) {
  if (typeof blob !== 'string' || blob.length % 2 !== 0) throw new Error('WRAP_MAC_FAILURE')
  let bytes
  try {
    bytes = hexToBytes(blob)
  } catch {
    throw new Error('WRAP_MAC_FAILURE')
  }
  if (bytes.length < NONCE_LEN + TAG_LEN) throw new Error('WRAP_MAC_FAILURE')

  const nonce = bytes.subarray(0, NONCE_LEN)
  const ct = bytes.subarray(NONCE_LEN, bytes.length - TAG_LEN)
  const tag = bytes.subarray(bytes.length - TAG_LEN)

  const expected = hmacSha256(wrapKey, concatBytes(nonce, ct))
  // A wrong password produces a wrong wrap key, which fails here rather than
  // silently returning garbage that would later corrupt a record.
  if (!timingSafeEqual(expected, tag)) throw new Error('WRAP_MAC_FAILURE')

  const stream = keystream(concatBytes(wrapKey, nonce), WRAP_INFO, ct.length)
  const out = new Uint8Array(ct.length)
  for (let i = 0; i < ct.length; i++) out[i] = ct[i] ^ stream[i]
  return out
}

export function wrapString(wrapKey, str) {
  return wrap(wrapKey, utf8ToBytes(String(str)))
}

export function unwrapString(wrapKey, blob) {
  return bytesToUtf8(unwrap(wrapKey, blob))
}
