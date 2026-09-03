/**
 * Registration, two-factor login, logout (feature F1).
 *
 * The registration pipeline, in order:
 *   1. validate the input
 *   2. hash the password with a fresh 128-bit salt (custom SHA-256)
 *   3. derive a wrap key from the password and the same salt
 *   4. the KMM generates RSA-2048 + secp256k1 + a MAC key
 *   5. private key material and the TOTP secret are wrapped with the wrap key
 *   6. every profile field is RSA-encrypted under the user's own public key
 *   7. a CBC-MAC is computed over the encrypted profile blob
 *   8. the row is inserted - at no point does plaintext reach the database
 *
 * Login is genuinely two-factor: step 1 verifies the password and returns a
 * short-lived challenge held in memory; no session cookie exists until step 2
 * verifies the TOTP code.
 */
import { Router } from 'express'
import config from '../config.js'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth } from '../middleware/auth.js'
import { hashPassword, verifyPassword } from '../crypto/password.js'
import { deriveWrapKey, wrapString, unwrapString } from '../crypto/keywrap.js'
import { generateTotpSecret, totpUri, verifyTotp, totpCode, secondsRemaining } from '../crypto/totp.js'
import { randomHex } from '../crypto/random.js'
import { generateKeyBundle, storeKeyBundle, loadPrivateKeys, fingerprintsOf } from '../services/keyManagement.js'
import { sealProfile } from '../services/records.js'
import { createSession, cookieOptions, revokeSession } from '../services/session.js'
import { putChallenge, takeChallenge, peekChallenge, dropChallenge, putMaterial, getMaterial } from '../services/sessionVault.js'
import { audit } from '../services/audit.js'

const router = Router()

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
  'qwerty123', 'letmein1', 'welcome1', 'admin123', 'iloveyou', 'sunshine',
  'princess', 'football', 'baseball', 'dragon123', 'monkey123', 'abc12345',
  'passw0rd', 'trustno1',
])

function validateRegistration(body) {
  const errors = []
  const username = String(body.username ?? '').trim()
  const password = String(body.password ?? '')
  const email = String(body.email ?? '').trim()
  const phone = String(body.phone ?? '').trim()
  const libraryCard = String(body.libraryCard ?? '').trim()
  const fullName = String(body.fullName ?? '').trim()
  const address = String(body.address ?? '').trim()

  if (!USERNAME_RE.test(username)) errors.push('Username must be 3-32 characters (letters, digits, . _ -).')
  if (password.length < 8) errors.push('Password must be at least 8 characters.')
  if (password.length > 200) errors.push('Password is too long.')
  if (COMMON_PASSWORDS.has(password.toLowerCase())) errors.push('That password is too common.')
  if (!EMAIL_RE.test(email)) errors.push('Enter a valid email address.')
  if (phone.length < 6 || phone.length > 32) errors.push('Enter a valid phone number.')
  if (libraryCard.length < 1 || libraryCard.length > 64) errors.push('Enter a library card number.')
  if (fullName.length < 1 || fullName.length > 120) errors.push('Enter your full name.')
  if (address.length > 300) errors.push('Address is too long.')

  return { errors, value: { username, password, email, phone, libraryCard, fullName, address } }
}

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
router.post(
  '/register',
  asyncHandler(async (req, res) => {
    const { errors, value } = validateRegistration(req.body ?? {})
    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))

    const existing = unwrap(
      await db.from('users').select('id').ilike('username', value.username).maybeSingle(),
      'username check',
    )
    if (existing) throw httpError(409, 'USERNAME_TAKEN', 'That username is already registered.')

    // 2 - salted hash of the password
    const { salt, hash } = hashPassword(value.password, config.PASSWORD_ITERATIONS)

    // 3 - the wrap key never leaves this process
    const wrapKey = deriveWrapKey(value.password, salt, config.KEYWRAP_ITERATIONS)

    // 4 - key generation
    const bundle = generateKeyBundle(config.RSA_BITS)

    // 5 - second factor secret, wrapped at rest
    const totpSecret = generateTotpSecret()

    // 6 + 7 - encrypted profile and its CBC-MAC
    const { encFields, profile_mac } = sealProfile(bundle.rsa, bundle.macKey, value)

    const user = unwrap(
      await db
        .from('users')
        .insert({
          username: value.username,
          role: 'patron',
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
      'user insert',
    )

    try {
      await storeKeyBundle(user.id, 1, bundle, wrapKey)
    } catch (err) {
      // Never leave an account without key material.
      await db.from('users').delete().eq('id', user.id)
      throw err
    }

    await audit(req, { userId: user.id, username: user.username, eventType: 'register', detail: `RSA-${config.RSA_BITS} + secp256k1 keys generated` })

    // The TOTP secret is returned exactly once and never stored in the clear.
    res.status(201).json({
      ok: true,
      userId: user.id,
      username: user.username,
      totpSecret,
      totpUri: totpUri(totpSecret, user.username),
      fingerprints: fingerprintsOf(bundle),
    })
  }),
)

// ---------------------------------------------------------------------------
// POST /api/auth/login  - factor 1
// ---------------------------------------------------------------------------
router.post(
  '/login',
  asyncHandler(async (req, res) => {
    const username = String(req.body?.username ?? '').trim()
    const password = String(req.body?.password ?? '')
    if (!username || !password) throw httpError(400, 'VALIDATION_ERROR', 'Username and password are required.')

    const user = unwrap(await db.from('users').select('*').ilike('username', username).maybeSingle(), 'login lookup')

    // Same work and the same message whether or not the account exists, so the
    // endpoint cannot be used to enumerate usernames.
    const salt = user?.password_salt ?? '00000000000000000000000000000000'
    const storedHash = user?.password_hash ?? 'f'.repeat(64)
    const passwordOk = verifyPassword(password, salt, storedHash, config.PASSWORD_ITERATIONS)

    if (!user || !passwordOk) {
      if (user) {
        await db.from('users').update({ failed_logins: (user.failed_logins ?? 0) + 1 }).eq('id', user.id)
      }
      await audit(req, {
        userId: user?.id ?? null,
        username,
        eventType: 'login',
        outcome: 'failure',
        detail: user ? 'wrong password' : 'unknown username',
      })
      throw httpError(401, 'BAD_CREDENTIALS', 'Incorrect username or password.')
    }

    if (user.status === 'suspended') {
      await audit(req, { userId: user.id, username, eventType: 'login', outcome: 'failure', detail: 'account suspended' })
      throw httpError(403, 'ACCOUNT_SUSPENDED', 'This account has been suspended by the librarian.')
    }

    const wrapKey = deriveWrapKey(password, user.password_salt, config.KEYWRAP_ITERATIONS)
    let totpSecret
    try {
      totpSecret = unwrapString(wrapKey, user.totp_secret_wrapped)
    } catch {
      throw httpError(500, 'KEY_UNWRAP_FAILED', 'Stored second-factor secret could not be unlocked.')
    }

    const challengeId = randomHex(16)
    putChallenge(challengeId, {
      userId: user.id,
      username: user.username,
      wrapKey,
      totpSecret,
      attempts: 0,
      expiresAt: Date.now() + config.CHALLENGE_TTL_MS,
    })

    await audit(req, { userId: user.id, username: user.username, eventType: 'login', detail: 'password accepted, awaiting second factor' })

    // No cookie yet - one factor is not authentication.
    res.json({
      stage: '2fa',
      challengeId,
      expiresIn: Math.round(config.CHALLENGE_TTL_MS / 1000),
      digits: 6,
    })
  }),
)

// ---------------------------------------------------------------------------
// POST /api/auth/verify-2fa  - factor 2
// ---------------------------------------------------------------------------
router.post(
  '/verify-2fa',
  asyncHandler(async (req, res) => {
    const challengeId = String(req.body?.challengeId ?? '')
    const code = String(req.body?.code ?? '').trim()

    const challenge = peekChallenge(challengeId)
    if (!challenge || challenge.expiresAt <= Date.now()) {
      dropChallenge(challengeId)
      throw httpError(401, 'CHALLENGE_EXPIRED', 'That sign-in attempt expired. Please start again.')
    }

    if (!verifyTotp(challenge.totpSecret, code, Date.now(), config.TOTP_WINDOW, config.TOTP_STEP_SECONDS)) {
      challenge.attempts += 1
      await audit(req, {
        userId: challenge.userId,
        username: challenge.username,
        eventType: '2fa',
        outcome: 'failure',
        detail: `attempt ${challenge.attempts}`,
      })
      if (challenge.attempts >= config.MAX_OTP_ATTEMPTS) {
        dropChallenge(challengeId)
        throw httpError(401, 'CHALLENGE_EXPIRED', 'Too many incorrect codes. Please sign in again.')
      }
      throw httpError(401, 'BAD_OTP', `Incorrect code. ${config.MAX_OTP_ATTEMPTS - challenge.attempts} attempt(s) left.`)
    }

    takeChallenge(challengeId) // single use

    const user = unwrap(await db.from('users').select('*').eq('id', challenge.userId).single(), 'user reload')
    if (user.status === 'suspended') throw httpError(403, 'ACCOUNT_SUSPENDED', 'This account has been suspended.')

    // Both factors passed: unwrap the private keys into process memory only.
    const keys = await loadPrivateKeys(user.id, challenge.wrapKey)
    const { token, session } = await createSession(user, req)
    putMaterial(session.id, {
      userId: user.id,
      keyVersion: keys.version,
      wrapKey: challenge.wrapKey,
      rsa: keys.rsa,
      ecc: keys.ecc,
      macKey: keys.macKey,
    })

    await db.from('users').update({ failed_logins: 0, last_login_at: new Date().toISOString() }).eq('id', user.id)

    await audit(req, { userId: user.id, username: user.username, eventType: '2fa', detail: 'second factor accepted' })

    res.cookie(config.SESSION_COOKIE, token, cookieOptions())
    res.json({
      user: publicUser({ ...user, key_version: keys.version }),
      session: { expiresAt: session.expires_at, idleTimeoutMinutes: config.SESSION_IDLE_MINUTES },
    })
  }),
)

// ---------------------------------------------------------------------------
router.post(
  '/logout',
  requireAuth,
  asyncHandler(async (req, res) => {
    await revokeSession(req.session.id, 'logout')
    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'logout' })
    res.clearCookie(config.SESSION_COOKIE, { path: '/' })
    res.json({ ok: true })
  }),
)

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json({
      user: publicUser(req.user),
      session: {
        expiresAt: req.session.expires_at,
        lastActiveAt: req.session.last_active_at,
        idleTimeoutMinutes: config.SESSION_IDLE_MINUTES,
        ipFingerprint: req.session.ip_fingerprint,
      },
      keysUnlocked: Boolean(getMaterial(req.session.id)),
      labRoutes: config.ENABLE_LAB_ROUTES,
    })
  }),
)

/**
 * Demo aid, mounted only when ENABLE_LAB_ROUTES is on: returns the code the
 * server currently expects for a pending challenge, so the app can be
 * demonstrated without an authenticator app on hand. Never enable in production.
 */
router.post(
  '/challenge-code',
  asyncHandler(async (req, res) => {
    if (!config.ENABLE_LAB_ROUTES) throw httpError(404, 'NOT_FOUND', 'Not available.')
    const challenge = peekChallenge(String(req.body?.challengeId ?? ''))
    if (!challenge) throw httpError(404, 'CHALLENGE_EXPIRED', 'No pending sign-in challenge.')
    res.json({
      code: totpCode(challenge.totpSecret, Date.now(), config.TOTP_STEP_SECONDS),
      secondsRemaining: secondsRemaining(Date.now(), config.TOTP_STEP_SECONDS),
      demoOnly: true,
    })
  }),
)

export function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    status: user.status,
    keyVersion: user.key_version,
    createdAt: user.created_at,
    lastLoginAt: user.last_login_at ?? null,
  }
}

export default router
