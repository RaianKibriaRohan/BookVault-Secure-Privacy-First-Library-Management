/**
 * Fine records (feature F5).
 *
 * The fine body - which book, the tier breakdown, the dates - is ECIES
 * encrypted and HMAC-tagged like any other record. Only the amount, the number
 * of days overdue and the payment status are mirrored in plaintext, because the
 * librarian genuinely needs those to run the library (feature A3). Knowing a
 * patron owes 185 BDT reveals nothing about what they were reading.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys, requirePatron } from '../middleware/auth.js'
import { sealEcc, openEcc, DOMAINS } from '../services/records.js'
import { audit } from '../services/audit.js'

const router = Router()

async function loadFines(req) {
  const rows = unwrap(
    await db.from('fines').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }),
    'fine list',
  )

  const items = []
  for (const row of rows) {
    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.fine)
    if (opened.integrity === 'tampered' && !row.tampered) {
      await db.from('fines').update({ tampered: true }).eq('id', row.id)
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'integrity_failure',
        outcome: 'warning',
        detail: `fine ${row.id} failed HMAC verification`,
      })
    }
    items.push({
      id: row.id,
      amount: Number(row.amount),
      daysOverdue: row.days_overdue,
      status: row.status,
      replacementNotice: row.replacement_notice,
      createdAt: row.created_at,
      paidAt: row.paid_at,
      keyVersion: row.key_version,
      integrity: opened.integrity,
      detail: opened.data
        ? {
            title: opened.data.title,
            author: opened.data.author,
            dueDate: opened.data.dueDate,
            returnedAt: opened.data.returnedAt,
            breakdown: opened.data.breakdown ?? [],
          }
        : null,
      raw: { ciphertext: row.ciphertext, hmacTag: row.hmac_tag },
    })
  }
  return items
}

function summarise(items) {
  const outstanding = items.filter(i => i.status === 'unpaid').reduce((sum, i) => sum + i.amount, 0)
  const paid = items.filter(i => i.status === 'paid').reduce((sum, i) => sum + i.amount, 0)
  return {
    outstanding,
    paid,
    total: outstanding + paid,
    unpaidCount: items.filter(i => i.status === 'unpaid').length,
    blocked: outstanding > 0,
    currency: 'BDT',
  }
}

router.get(
  '/',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const fines = await loadFines(req)
    res.json({ fines, summary: summarise(fines) })
  }),
)

/** Payment is simulated, as the proposal specifies. */
async function payOne(req, row) {
  const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.fine)
  const paidAt = new Date().toISOString()
  const patch = { status: 'paid', paid_at: paidAt }

  // Re-seal so the encrypted body agrees with the plaintext status mirror.
  if (opened.integrity === 'ok') {
    const sealed = sealEcc(req.keys.ecc.pub, req.keys.macKey, { ...opened.data, status: 'paid', paidAt }, DOMAINS.fine)
    patch.ciphertext = sealed.ciphertext
    patch.hmac_tag = sealed.hmac_tag
    patch.key_version = req.keys.keyVersion
  }
  unwrap(await db.from('fines').update(patch).eq('id', row.id).select('id').single(), 'fine payment')
  await audit(req, {
    userId: req.user.id,
    username: req.user.username,
    eventType: 'fine_paid',
    detail: `${Number(row.amount)} BDT cleared (simulated payment)`,
  })
}

router.post(
  '/:id/pay',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const row = unwrap(
      await db.from('fines').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle(),
      'fine read',
    )
    if (!row) throw httpError(404, 'NOT_FOUND', 'No such fine.')
    if (row.status === 'paid') throw httpError(409, 'ALREADY_PAID', 'That fine has already been paid.')

    await payOne(req, row)
    const fines = await loadFines(req)
    res.json({ ok: true, paid: Number(row.amount), summary: summarise(fines) })
  }),
)

router.post(
  '/pay-all',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const rows = unwrap(
      await db.from('fines').select('*').eq('user_id', req.user.id).eq('status', 'unpaid'),
      'fine list',
    )
    if (!rows.length) throw httpError(409, 'NOTHING_DUE', 'You have no outstanding fines.')

    let total = 0
    for (const row of rows) {
      await payOne(req, row)
      total += Number(row.amount)
    }
    const fines = await loadFines(req)
    res.json({ ok: true, paid: total, count: rows.length, summary: summarise(fines) })
  }),
)

export default router
