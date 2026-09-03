/**
 * Authentication and role-based access control (security feature 7).
 *
 * RBAC is enforced here, server-side, on every request. The React app hides
 * admin navigation from patrons, but that is cosmetic - the only thing that
 * actually stops a patron reaching /api/admin/* is requireRole below, and every
 * refusal is written to the audit log.
 */
import config from '../config.js'
import { httpError, asyncHandler } from './errors.js'
import { validateSession } from '../services/session.js'
import { getMaterial } from '../services/sessionVault.js'
import { audit } from '../services/audit.js'

export const requireAuth = asyncHandler(async (req, res, next) => {
  const token = req.cookies?.[config.SESSION_COOKIE]
  const { session, user } = await validateSession(token, req)

  if (user.status === 'suspended') {
    throw httpError(403, 'ACCOUNT_SUSPENDED', 'This account has been suspended by the librarian.')
  }

  req.session = session
  req.user = user
  next()
})

/**
 * Attaches the caller's unwrapped key material. It only exists in this
 * process's memory (see services/sessionVault.js), so after a server restart a
 * live cookie is authenticated but locked - the honest answer is to ask the
 * user to sign in again rather than to weaken key storage.
 */
export const requireKeys = (req, res, next) => {
  const material = getMaterial(req.session.id)
  if (!material) {
    return next(
      httpError(409, 'KEYS_LOCKED', 'Your encryption keys are locked. Please sign in again to unlock them.'),
    )
  }
  req.keys = material
  next()
}

export const requireRole = (...roles) =>
  asyncHandler(async (req, res, next) => {
    if (!req.user) throw httpError(401, 'NO_SESSION', 'Not signed in.')
    if (!roles.includes(req.user.role)) {
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'rbac_denied',
        outcome: 'failure',
        detail: `${req.method} ${req.originalUrl} requires ${roles.join('/')}, caller is ${req.user.role}`,
      })
      throw httpError(403, 'FORBIDDEN', `This area is restricted to ${roles.join(' or ')} accounts.`)
    }
    next()
  })

export const requireAdmin = requireRole('admin')
export const requirePatron = requireRole('patron')
