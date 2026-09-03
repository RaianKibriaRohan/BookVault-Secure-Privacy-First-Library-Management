/**
 * Audit trail (feature A5).
 *
 * Metadata only - who, what, when, from where, and whether it succeeded. No
 * ciphertext, no decrypted content, no key material ever reaches this table.
 * Auditing must never break a request, so every failure here is swallowed.
 */
import { db } from '../db/supabase.js'

export const EVENT_TYPES = Object.freeze([
  'register',
  'login',
  '2fa',
  'logout',
  'session_hijack_suspected',
  'session_expired',
  'rbac_denied',
  'borrow',
  'return',
  'fine_issued',
  'fine_paid',
  'review_create',
  'review_update',
  'review_delete',
  'profile_update',
  'key_rotation',
  'chat_send',
  'account_status_change',
  'book_create',
  'book_update',
  'book_delete',
  'integrity_failure',
  'lab_tamper',
])

export async function audit(req, { userId = null, username = null, eventType, outcome = 'success', detail = '' }) {
  try {
    await db.from('audit_logs').insert({
      user_id: userId,
      username,
      event_type: eventType,
      outcome,
      detail: String(detail).slice(0, 500),
      ip: req?.ip ?? null,
    })
  } catch (err) {
    console.error('[audit] failed to record event', eventType, err?.message)
  }
}
