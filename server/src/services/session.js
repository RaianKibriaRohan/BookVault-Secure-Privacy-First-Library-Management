/**
 * Secure session management (security feature 9, lab requirement 12).
 *
 *   - 256-bit tokens from the hand-written CSPRNG
 *   - only SHA-256(token) is stored, so a leaked database cannot be replayed
 *   - HttpOnly + SameSite cookie, so script on the page cannot read the token
 *   - IP and user-agent fingerprints detect a stolen cookie used elsewhere
 *   - 30-minute idle timeout and a 12-hour absolute lifetime
 *   - one live session per account: signing in elsewhere kills the old one
 */
import config from '../config.js'
import { db, unwrap } from '../db/supabase.js'
import { randomHex } from '../crypto/random.js'
import { sha256Hex } from '../crypto/sha256.js'
import { httpError } from '../middleware/errors.js'
import { audit } from './audit.js'
import { dropMaterial, dropUser } from './sessionVault.js'

export function hashToken(token) {
  return sha256Hex(token)
}

export function fingerprintIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  const raw = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim() || req.ip || ''
  return sha256Hex(`ip:${raw}`).slice(0, 32)
}

export function fingerprintUa(req) {
  return sha256Hex(`ua:${req.headers['user-agent'] ?? ''}`).slice(0, 32)
}

export async function createSession(user, req) {
  // Single-session enforcement: everything else for this account dies now.
  await revokeAllForUser(user.id, 'new_login')

  const token = randomHex(32) // 256 bits of entropy
  const now = Date.now()
  const row = unwrap(
    await db
      .from('sessions')
      .insert({
        user_id: user.id,
        token_hash: hashToken(token),
        ip_fingerprint: fingerprintIp(req),
        ua_fingerprint: fingerprintUa(req),
        expires_at: new Date(now + config.SESSION_ABSOLUTE_HOURS * 3_600_000).toISOString(),
        last_active_at: new Date(now).toISOString(),
      })
      .select()
      .single(),
    'session insert',
  )
  return { token, session: row }
}

export function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.isProd,
    maxAge: config.SESSION_ABSOLUTE_HOURS * 3_600_000,
    path: '/',
  }
}

export async function validateSession(token, req) {
  if (!token || typeof token !== 'string') throw httpError(401, 'NO_SESSION', 'Not signed in.')

  const session = unwrap(
    await db.from('sessions').select('*').eq('token_hash', hashToken(token)).maybeSingle(),
    'session lookup',
  )
  if (!session) throw httpError(401, 'NO_SESSION', 'Not signed in.')

  if (session.revoked) {
    dropMaterial(session.id)
    throw httpError(401, 'SESSION_REVOKED', 'This session has been ended. Please sign in again.')
  }

  const now = Date.now()

  if (new Date(session.expires_at).getTime() <= now) {
    await revokeSession(session.id, 'expired')
    throw httpError(401, 'SESSION_EXPIRED', 'Your session has expired. Please sign in again.')
  }

  const idleMs = now - new Date(session.last_active_at).getTime()
  if (idleMs > config.SESSION_IDLE_MINUTES * 60_000) {
    await revokeSession(session.id, 'idle_timeout')
    throw httpError(401, 'SESSION_IDLE_TIMEOUT', `Signed out after ${config.SESSION_IDLE_MINUTES} minutes of inactivity.`)
  }

  // Hijack detection: the same token arriving from a different client.
  const ip = fingerprintIp(req)
  const ua = fingerprintUa(req)
  if (session.ip_fingerprint !== ip || session.ua_fingerprint !== ua) {
    await revokeSession(session.id, 'fingerprint_mismatch')
    await audit(req, {
      userId: session.user_id,
      eventType: 'session_hijack_suspected',
      outcome: 'warning',
      detail: `ip match=${session.ip_fingerprint === ip}, ua match=${session.ua_fingerprint === ua}`,
    })
    throw httpError(401, 'SESSION_FINGERPRINT_MISMATCH', 'Session fingerprint changed. Please sign in again.')
  }

  const user = unwrap(
    await db.from('users').select('*').eq('id', session.user_id).maybeSingle(),
    'session user lookup',
  )
  if (!user) {
    await revokeSession(session.id, 'user_missing')
    throw httpError(401, 'NO_SESSION', 'Not signed in.')
  }

  await touchSession(session.id)
  return { session, user }
}

export async function touchSession(sessionId) {
  await db.from('sessions').update({ last_active_at: new Date().toISOString() }).eq('id', sessionId)
}

export async function revokeSession(sessionId, reason = 'logout') {
  dropMaterial(sessionId)
  await db.from('sessions').update({ revoked: true, revoked_reason: reason }).eq('id', sessionId)
}

export async function revokeAllForUser(userId, reason = 'revoked', exceptId = null) {
  let query = db.from('sessions').update({ revoked: true, revoked_reason: reason }).eq('user_id', userId).eq('revoked', false)
  if (exceptId) query = query.neq('id', exceptId)
  await query
  if (exceptId) {
    const rows = unwrap(await db.from('sessions').select('id').eq('user_id', userId).eq('revoked', true), 'revoke sweep')
    for (const row of rows ?? []) if (row.id !== exceptId) dropMaterial(row.id)
  } else {
    dropUser(userId)
  }
}

export async function listSessions(userId) {
  return unwrap(
    await db
      .from('sessions')
      .select('id, created_at, last_active_at, expires_at, revoked, revoked_reason, ip_fingerprint')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(10),
    'session list',
  )
}
