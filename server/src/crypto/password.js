/**
 * Password hashing (feature F1, lab requirement 3).
 *
 *   salt = 128 random bits
 *   hash = SHA-256(salt || password), iterated PASSWORD_ITERATIONS times
 *
 * Stored as two columns (`password_salt`, `password_hash`) - the `salt:hash`
 * form described in the proposal, split for query clarity. The salt makes two
 * identical passwords hash differently, so a stolen table cannot be attacked
 * with a single precomputed rainbow table.
 */
import { sha256 } from './sha256.js'
import { randomHex } from './random.js'
import { utf8ToBytes, bytesToHex, hexToBytes, concatBytes, timingSafeEqualHex } from './bytes.js'

const ITERATIONS = Math.max(1, Number.parseInt(process.env.PASSWORD_ITERATIONS ?? '1', 10) || 1)

export function hashPasswordWithSalt(password, saltHex, iterations = ITERATIONS) {
  const salt = hexToBytes(saltHex)
  let digest = sha256(concatBytes(salt, utf8ToBytes(String(password))))
  for (let i = 1; i < iterations; i++) {
    digest = sha256(concatBytes(salt, digest))
  }
  return bytesToHex(digest)
}

export function hashPassword(password, iterations = ITERATIONS) {
  const salt = randomHex(16) // 128-bit salt
  return { salt, hash: hashPasswordWithSalt(password, salt, iterations) }
}

export function verifyPassword(password, saltHex, expectedHash, iterations = ITERATIONS) {
  if (typeof saltHex !== 'string' || typeof expectedHash !== 'string') return false
  return timingSafeEqualHex(hashPasswordWithSalt(password, saltHex, iterations), expectedHash)
}

/** Combined form, as described in the proposal. */
export function formatStored(salt, hash) {
  return `${salt}:${hash}`
}
