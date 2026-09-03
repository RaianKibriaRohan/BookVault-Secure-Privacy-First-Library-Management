/**
 * Encrypted profile management (feature F9, security feature 3).
 *
 * Read  : verify the CBC-MAC over the encrypted blob, then RSA-decrypt each
 *         field with the caller's own private key. Plaintext exists only in
 *         this process, for the duration of the response.
 * Write : re-encrypt the changed fields, recompute the CBC-MAC over all of
 *         them, store. Nothing is ever written back in the clear.
 *
 * There is no route by which one user can read another user's profile - the
 * query is always scoped to req.user.id, and even if it were not, the record
 * could only be decrypted with that user's private key.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys } from '../middleware/auth.js'
import { openProfile, resealProfile, PROFILE_ORDER, PROFILE_FIELDS } from '../services/records.js'
import { audit } from '../services/audit.js'

const router = Router()

const LIMITS = {
  email: 190,
  phone: 32,
  libraryCard: 64,
  fullName: 120,
  address: 300,
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

router.get(
  '/',
  requireAuth,
  requireKeys,
  asyncHandler(async (req, res) => {
    const row = unwrap(await db.from('users').select('*').eq('id', req.user.id).single(), 'profile read')
    const opened = openProfile(req.keys.rsa, req.keys.macKey, row)

    res.json({
      fields: opened.fields,
      macValid: opened.macValid,
      decryptable: opened.decryptable,
      keyVersion: row.key_version,
      updatedAt: row.updated_at,
      // Shown in the UI so a patron can see exactly what the database holds.
      ciphertext: Object.fromEntries(PROFILE_ORDER.map(name => [name, row[PROFILE_FIELDS[name]] ?? ''])),
      profileMac: row.profile_mac,
    })
  }),
)

router.put(
  '/',
  requireAuth,
  requireKeys,
  asyncHandler(async (req, res) => {
    const body = req.body ?? {}
    const changes = {}
    const errors = []

    for (const name of PROFILE_ORDER) {
      if (!(name in body)) continue
      const value = String(body[name] ?? '').trim()
      if (value.length > LIMITS[name]) errors.push(`${name} is too long (max ${LIMITS[name]}).`)
      if (name === 'email' && value && !EMAIL_RE.test(value)) errors.push('Enter a valid email address.')
      if (name === 'fullName' && !value) errors.push('Full name cannot be empty.')
      changes[name] = value
    }

    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))
    if (Object.keys(changes).length === 0) throw httpError(400, 'NO_CHANGES', 'Nothing to update.')

    const row = unwrap(await db.from('users').select('*').eq('id', req.user.id).single(), 'profile read')
    const current = {}
    for (const name of PROFILE_ORDER) current[PROFILE_FIELDS[name]] = row[PROFILE_FIELDS[name]] ?? ''

    const { encFields, profile_mac } = resealProfile(req.keys.rsa, req.keys.macKey, current, changes)

    unwrap(
      await db
        .from('users')
        .update({ ...encFields, profile_mac, updated_at: new Date().toISOString() })
        .eq('id', req.user.id)
        .select('id')
        .single(),
      'profile write',
    )

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'profile_update',
      detail: `re-encrypted: ${Object.keys(changes).join(', ')}`,
    })

    res.json({ ok: true, reEncrypted: Object.keys(changes) })
  }),
)

export default router
