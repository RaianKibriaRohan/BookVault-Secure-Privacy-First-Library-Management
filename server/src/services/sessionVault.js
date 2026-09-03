/**
 * The process-memory key vault.
 *
 * This module is what makes "even the Head Librarian cannot read patron data"
 * a structural fact rather than a policy. Private keys are stored in the
 * database only in wrapped form, under a key derived from the patron's
 * password. They are unwrapped exactly once - during the second authentication
 * factor - and the plaintext key material is held here, in RAM, keyed by
 * session id.
 *
 * Consequences, all intentional:
 *   - a database dump contains no usable private key;
 *   - an administrator with full SQL access still cannot decrypt a record;
 *   - restarting the API forces everyone to sign in again, because the vault
 *     is gone. That is the honest price of not persisting key material.
 */
import config from '../config.js'

/** sessionId -> { userId, keyVersion, wrapKey, rsa, ecc, macKey } */
const material = new Map()

/** challengeId -> { userId, username, wrapKey, totpSecret, expiresAt, attempts, ip } */
const challenges = new Map()

export function putMaterial(sessionId, value) {
  material.set(sessionId, value)
}

export function getMaterial(sessionId) {
  return material.get(sessionId) ?? null
}

export function dropMaterial(sessionId) {
  material.delete(sessionId)
}

/** Used when an account is suspended or every session is revoked at once. */
export function dropUser(userId) {
  for (const [sessionId, value] of material) {
    if (value.userId === userId) material.delete(sessionId)
  }
}

export function updateMaterial(sessionId, patch) {
  const current = material.get(sessionId)
  if (current) material.set(sessionId, { ...current, ...patch })
}

function sweepChallenges(now = Date.now()) {
  for (const [id, challenge] of challenges) {
    if (challenge.expiresAt <= now) challenges.delete(id)
  }
}

export function putChallenge(id, challenge) {
  sweepChallenges()
  challenges.set(id, challenge)
}

export function peekChallenge(id) {
  sweepChallenges()
  return challenges.get(id) ?? null
}

/** Reads and removes a challenge - a challenge is single-use by construction. */
export function takeChallenge(id) {
  sweepChallenges()
  const challenge = challenges.get(id) ?? null
  if (challenge) challenges.delete(id)
  return challenge
}

export function dropChallenge(id) {
  challenges.delete(id)
}

export function stats() {
  sweepChallenges()
  return {
    unlockedSessions: material.size,
    pendingChallenges: challenges.size,
    challengeTtlMs: config.CHALLENGE_TTL_MS,
  }
}
