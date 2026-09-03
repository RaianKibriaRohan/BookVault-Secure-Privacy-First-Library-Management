/**
 * CBC-MAC over 128-bit blocks - the integrity tag on the encrypted profile blob
 * (feature F9 / security requirement 8).
 *
 * The lab specification forbids symmetric ciphers, and AES is a symmetric
 * cipher, so the 128-bit block function is built from our own hash instead:
 *
 *   E(K, B) = SHA-256(K || B)[0..16]
 *
 * It is a keyed one-way compression rather than a permutation, which is fine
 * here: CBC-MAC only ever evaluates E in the forward direction.
 *
 * Chaining is textbook CBC:  C_0 = 0^128,  C_i = E(K, C_{i-1} XOR B_i),
 * and the tag is the final chaining value.
 *
 * Padding: the message is prefixed with its length as an 8-byte big-endian
 * integer and then zero-padded to a multiple of 16. Plain zero-padding of a
 * raw message would let an attacker forge the tag of a longer message from the
 * tag of a shorter one (the classic CBC-MAC extension attack, and the reason
 * textbook CBC-MAC is only secure for fixed-length inputs). Binding the length
 * into the very first block makes every distinct message a distinct block
 * sequence.
 */
import { sha256 } from './sha256.js'
import { utf8ToBytes, bytesToHex, concatBytes, timingSafeEqualHex } from './bytes.js'

const BLOCK = 16

/** The keyed 128-bit block function. */
function blockFunction(key, block) {
  return sha256(concatBytes(key, block)).subarray(0, BLOCK)
}

function padWithLength(message) {
  const bitLen = BigInt(message.length) * 8n
  const prefix = new Uint8Array(8)
  let len = bitLen
  for (let i = 7; i >= 0; i--) {
    prefix[i] = Number(len & 0xffn)
    len >>= 8n
  }
  const body = concatBytes(prefix, message)
  const padded = new Uint8Array(Math.ceil(body.length / BLOCK) * BLOCK || BLOCK)
  padded.set(body, 0)
  return padded
}

export function cbcMac(key, message) {
  const k = typeof key === 'string' ? utf8ToBytes(key) : key
  const msg = typeof message === 'string' ? utf8ToBytes(message) : message
  const padded = padWithLength(msg)

  let chain = new Uint8Array(BLOCK) // C_0 = zero IV
  const xored = new Uint8Array(BLOCK)
  for (let offset = 0; offset < padded.length; offset += BLOCK) {
    for (let i = 0; i < BLOCK; i++) xored[i] = chain[i] ^ padded[offset + i]
    chain = blockFunction(k, xored)
  }
  return chain
}

export function cbcMacHex(key, message) {
  return bytesToHex(cbcMac(key, message))
}

export function verifyCbcMac(key, message, tagHex) {
  if (typeof tagHex !== 'string') return false
  return timingSafeEqualHex(cbcMacHex(key, message), tagHex)
}
