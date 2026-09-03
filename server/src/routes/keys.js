/**
 * Key management endpoints (feature F10 / security feature 4).
 *
 * GET  /api/keys         public key material, fingerprints and version history
 * POST /api/keys/rotate  full privacy reset - new key pair, every record
 *                        re-encrypted, old keys destroyed
 *
 * No private key material is ever serialised out of this API.
 */
import { Router } from 'express'
import config from '../config.js'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys } from '../middleware/auth.js'
import { verifyPassword } from '../crypto/password.js'
import { deriveWrapKey } from '../crypto/keywrap.js'
import { loadPublicKeys, listKeyVersions, rotateKeys } from '../services/keyManagement.js'
import { putMaterial } from '../services/sessionVault.js'
import { listSessions } from '../services/session.js'
import { audit } from '../services/audit.js'

const router = Router()

router.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const keys = await loadPublicKeys(req.user.id)
    const history = await listKeyVersions(req.user.id)
    const sessions = await listSessions(req.user.id)

    res.json({
      version: keys.version,
      createdAt: keys.createdAt,
      rsa: {
        fingerprint: keys.fingerprints.rsa,
        modulusBits: keys.fingerprints.rsaBits,
        publicExponent: '65537',
        algorithm: 'RSA-OAEP (SHA-256, MGF1)',
        usedFor: 'profile fields and chat message bodies',
      },
      ecc: {
        fingerprint: keys.fingerprints.ecc,
        curve: keys.fingerprints.curve,
        algorithm: 'ECIES (ECDH + counter-mode KDF, encrypt-then-MAC)',
        usedFor: 'checkout records, fines and private reviews',
      },
      mac: {
        algorithm: 'HMAC-SHA256 on records, CBC-MAC on the profile blob',
      },
      history,
      sessions: sessions.map(s => ({
        id: s.id,
        createdAt: s.created_at,
        lastActiveAt: s.last_active_at,
        expiresAt: s.expires_at,
        revoked: s.revoked,
        reason: s.revoked_reason,
        current: s.id === req.session.id,
      })),
    })
  }),
)

router.post(
  '/rotate',
  requireAuth,
  requireKeys,
  asyncHandler(async (req, res) => {
    const password = String(req.body?.password ?? '')
    if (!password) throw httpError(400, 'VALIDATION_ERROR', 'Confirm your password to rotate your keys.')

    const row = unwrap(
      await db.from('users').select('password_salt, password_hash').eq('id', req.user.id).single(),
      'rotation auth',
    )
    if (!verifyPassword(password, row.password_salt, row.password_hash, config.PASSWORD_ITERATIONS)) {
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'key_rotation',
        outcome: 'failure',
        detail: 'password confirmation failed',
      })
      throw httpError(401, 'BAD_CREDENTIALS', 'That password is not correct.')
    }

    const wrapKey = deriveWrapKey(password, row.password_salt, config.KEYWRAP_ITERATIONS)
    const steps = []
    const result = await rotateKeys(req.user.id, wrapKey, step => steps.push(step))

    // Keep this session working under the new keys.
    putMaterial(req.session.id, {
      userId: req.user.id,
      keyVersion: result.material.version,
      wrapKey,
      rsa: result.material.rsa,
      ecc: result.material.ecc,
      macKey: result.material.macKey,
    })

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'key_rotation',
      detail: `v${result.report.from} -> v${result.report.to}; re-encrypted ` +
        `${result.report.checkouts.rekeyed} checkouts, ${result.report.fines.rekeyed} fines, ` +
        `${result.report.reviews.rekeyed} reviews, ${result.report.chat.rekeyed} messages`,
    })

    res.json({
      ok: true,
      version: result.version,
      report: result.report,
      fingerprints: result.fingerprints,
      steps,
    })
  }),
)

export default router
