/**
 * HMAC-SHA256, RFC 2104 / FIPS 198-1.
 *
 *   HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 *
 * K' is the key padded to the 64-byte block size of SHA-256, or the hash of the
 * key when the key is longer than a block. This is the integrity primitive
 * behind every encrypted record in BookVault (encrypt-then-MAC).
 */
import { sha256 } from './sha256.js'
import { utf8ToBytes, bytesToHex, concatBytes, timingSafeEqualHex } from './bytes.js'

const BLOCK_SIZE = 64

function normaliseKey(key) {
  let k = typeof key === 'string' ? utf8ToBytes(key) : key
  if (k.length > BLOCK_SIZE) k = sha256(k)
  const padded = new Uint8Array(BLOCK_SIZE) // zero-filled = right-padded with 0x00
  padded.set(k, 0)
  return padded
}

export function hmacSha256(key, message) {
  const k = normaliseKey(key)
  const msg = typeof message === 'string' ? utf8ToBytes(message) : message

  const ipad = new Uint8Array(BLOCK_SIZE)
  const opad = new Uint8Array(BLOCK_SIZE)
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = k[i] ^ 0x36
    opad[i] = k[i] ^ 0x5c
  }

  const inner = sha256(concatBytes(ipad, msg))
  return sha256(concatBytes(opad, inner))
}

export function hmacSha256Hex(key, message) {
  return bytesToHex(hmacSha256(key, message))
}

/** Constant-time tag verification - never compare MACs with ===. */
export function verifyHmac(key, message, tagHex) {
  if (typeof tagHex !== 'string') return false
  return timingSafeEqualHex(hmacSha256Hex(key, message), tagHex)
}
