/**
 * Head Librarian console (features A1-A5).
 *
 * Every route here is behind requireAdmin. The theme of the whole file is that
 * the librarian is powerful over the LIBRARY and powerless over PATRON DATA:
 * they can add books, suspend accounts, chase fines and read the audit trail,
 * but there is no code path in this file that decrypts a patron record - and
 * even if somebody added one, the key material simply is not available to this
 * session (see services/sessionVault.js).
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireAdmin } from '../middleware/auth.js'
import { revokeAllForUser } from '../services/session.js'
import { audit, EVENT_TYPES } from '../services/audit.js'

const router = Router()

router.use(requireAuth, requireAdmin)

router.get(
  '/stats',
  asyncHandler(async (req, res) => {
    const [users, books, checkouts, fines, messages, events] = await Promise.all([
      db.from('users').select('id, role, status'),
      db.from('books').select('total_copies, available_copies'),
      db.from('checkouts').select('status, due_date'),
      db.from('fines').select('amount, status'),
      db.from('chat_messages').select('id, recipient_id, read_at'),
      db.from('audit_logs').select('id, outcome, created_at').gte('created_at', new Date(Date.now() - 86_400_000).toISOString()),
    ])

    const userRows = unwrap(users, 'stats users')
    const bookRows = unwrap(books, 'stats books')
    const checkoutRows = unwrap(checkouts, 'stats checkouts')
    const fineRows = unwrap(fines, 'stats fines')
    const messageRows = unwrap(messages, 'stats messages')
    const eventRows = unwrap(events, 'stats events')

    const today = new Date().toISOString().slice(0, 10)

    res.json({
      patrons: userRows.filter(u => u.role === 'patron').length,
      admins: userRows.filter(u => u.role === 'admin').length,
      suspended: userRows.filter(u => u.status === 'suspended').length,
      titles: bookRows.length,
      copies: bookRows.reduce((n, b) => n + b.total_copies, 0),
      copiesOnLoan: bookRows.reduce((n, b) => n + (b.total_copies - b.available_copies), 0),
      activeCheckouts: checkoutRows.filter(c => c.status === 'active').length,
      overdueCheckouts: checkoutRows.filter(c => c.status === 'active' && c.due_date < today).length,
      outstandingFines: fineRows.filter(f => f.status === 'unpaid').reduce((n, f) => n + Number(f.amount), 0),
      paidFines: fineRows.filter(f => f.status === 'paid').reduce((n, f) => n + Number(f.amount), 0),
      unreadMessages: messageRows.filter(m => m.recipient_id === req.user.id && !m.read_at).length,
      events24h: eventRows.length,
      failures24h: eventRows.filter(e => e.outcome === 'failure').length,
      warnings24h: eventRows.filter(e => e.outcome === 'warning').length,
    })
  }),
)

/**
 * A2 - account management.
 * The select list below is explicit and contains no *_enc column, so it is
 * structurally impossible for this endpoint to leak an encrypted profile field,
 * let alone a decrypted one.
 */
router.get(
  '/users',
  asyncHandler(async (req, res) => {
    const rows = unwrap(
      await db
        .from('users')
        .select('id, username, role, status, key_version, created_at, last_login_at, failed_logins')
        .order('created_at', { ascending: false }),
      'user list',
    )

    const [checkouts, fines] = await Promise.all([
      db.from('checkouts').select('user_id, status'),
      db.from('fines').select('user_id, status, amount'),
    ])
    const checkoutRows = unwrap(checkouts, 'user checkouts')
    const fineRows = unwrap(fines, 'user fines')

    res.json({
      users: rows.map(u => ({
        id: u.id,
        username: u.username,
        role: u.role,
        status: u.status,
        keyVersion: u.key_version,
        createdAt: u.created_at,
        lastLoginAt: u.last_login_at,
        failedLogins: u.failed_logins,
        checkouts: checkoutRows.filter(c => c.user_id === u.id).length,
        activeCheckouts: checkoutRows.filter(c => c.user_id === u.id && c.status === 'active').length,
        outstandingFines: fineRows
          .filter(f => f.user_id === u.id && f.status === 'unpaid')
          .reduce((n, f) => n + Number(f.amount), 0),
      })),
      note: 'Encrypted profile fields are deliberately not selected by this endpoint.',
    })
  }),
)

router.patch(
  '/users/:id/status',
  asyncHandler(async (req, res) => {
    const status = String(req.body?.status ?? '')
    if (!['active', 'suspended'].includes(status)) {
      throw httpError(400, 'VALIDATION_ERROR', 'Status must be active or suspended.')
    }
    if (req.params.id === req.user.id) throw httpError(400, 'SELF_ACTION', 'You cannot change your own account status.')

    const target = unwrap(await db.from('users').select('id, username, role, status').eq('id', req.params.id).maybeSingle(), 'user read')
    if (!target) throw httpError(404, 'NOT_FOUND', 'No such account.')
    if (target.role === 'admin') throw httpError(403, 'FORBIDDEN', 'Librarian accounts cannot be suspended from here.')

    unwrap(
      await db.from('users').update({ status, updated_at: new Date().toISOString() }).eq('id', target.id).select('id').single(),
      'status update',
    )

    // Suspension takes effect immediately: kill the sessions and forget the keys.
    if (status === 'suspended') await revokeAllForUser(target.id, 'account_suspended')

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'account_status_change',
      outcome: status === 'suspended' ? 'warning' : 'success',
      detail: `${target.username} -> ${status}`,
    })

    res.json({ ok: true, username: target.username, status })
  }),
)

/** A3 - fine dashboard. Amounts are plaintext; the record body is not. */
router.get(
  '/fines',
  asyncHandler(async (req, res) => {
    const rows = unwrap(await db.from('fines').select('*').order('created_at', { ascending: false }), 'fine list')
    const userIds = [...new Set(rows.map(r => r.user_id))]
    const users = userIds.length
      ? unwrap(await db.from('users').select('id, username, status').in('id', userIds), 'fine users')
      : []
    const nameOf = new Map(users.map(u => [u.id, u]))

    res.json({
      fines: rows.map(r => ({
        id: r.id,
        userId: r.user_id,
        username: nameOf.get(r.user_id)?.username ?? 'unknown',
        userStatus: nameOf.get(r.user_id)?.status ?? 'active',
        amount: Number(r.amount),
        daysOverdue: r.days_overdue,
        status: r.status,
        replacementNotice: r.replacement_notice,
        createdAt: r.created_at,
        paidAt: r.paid_at,
        // Shown in the UI to make the point: this is all the librarian gets.
        ciphertext: r.ciphertext,
        hmacTag: r.hmac_tag,
      })),
      summary: {
        outstanding: rows.filter(r => r.status === 'unpaid').reduce((n, r) => n + Number(r.amount), 0),
        paid: rows.filter(r => r.status === 'paid').reduce((n, r) => n + Number(r.amount), 0),
        unpaidCount: rows.filter(r => r.status === 'unpaid').length,
        currency: 'BDT',
      },
    })
  }),
)

/** A5 - audit log viewer. */
router.get(
  '/audit',
  asyncHandler(async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number.parseInt(req.query.limit ?? '100', 10) || 100))
    let query = db.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(limit)

    if (req.query.event) query = query.eq('event_type', String(req.query.event))
    if (req.query.outcome) query = query.eq('outcome', String(req.query.outcome))
    if (req.query.username) query = query.ilike('username', `%${String(req.query.username).replace(/[%,()]/g, '')}%`)

    const rows = unwrap(await query, 'audit list')
    res.json({
      events: rows.map(r => ({
        id: r.id,
        userId: r.user_id,
        username: r.username,
        eventType: r.event_type,
        outcome: r.outcome,
        detail: r.detail,
        ip: r.ip,
        createdAt: r.created_at,
      })),
      eventTypes: EVENT_TYPES,
    })
  }),
)

/**
 * The proof endpoint.
 *
 * This returns the encrypted tables exactly as the database holds them. It is
 * the librarian looking straight at patron records with full SQL-level access -
 * and seeing nothing but hex. Use it in the demo alongside a patron's own
 * decrypted vault view of the same rows.
 */
const ENCRYPTED_TABLES = {
  checkouts: ['id', 'user_id', 'ciphertext', 'hmac_tag', 'key_version', 'due_date', 'status', 'created_at'],
  reviews: ['id', 'user_id', 'ciphertext', 'hmac_tag', 'key_version', 'created_at'],
  fines: ['id', 'user_id', 'ciphertext', 'hmac_tag', 'key_version', 'amount', 'status', 'created_at'],
  chat_messages: ['id', 'sender_id', 'recipient_id', 'body_for_recipient', 'hmac_tag', 'ts', 'created_at'],
}

router.get(
  '/encrypted/:table',
  asyncHandler(async (req, res) => {
    const table = String(req.params.table)
    const columns = ENCRYPTED_TABLES[table]
    if (!columns) throw httpError(404, 'NOT_FOUND', 'That table is not available here.')

    const rows = unwrap(
      await db.from(table).select(columns.join(', ')).order('created_at', { ascending: false }).limit(100),
      'encrypted read',
    )

    const ids = [...new Set(rows.flatMap(r => [r.user_id, r.sender_id, r.recipient_id].filter(Boolean)))]
    const users = ids.length ? unwrap(await db.from('users').select('id, username').in('id', ids), 'row owners') : []
    const nameOf = new Map(users.map(u => [u.id, u.username]))

    res.json({
      table,
      columns,
      rows: rows.map(r => ({
        ...r,
        username: nameOf.get(r.user_id ?? r.sender_id) ?? null,
        recipientName: r.recipient_id ? (nameOf.get(r.recipient_id) ?? null) : undefined,
      })),
      note: 'This is the complete view an administrator has of patron records. The payload column is ciphertext; the librarian holds no key that opens it.',
    })
  }),
)

export default router
