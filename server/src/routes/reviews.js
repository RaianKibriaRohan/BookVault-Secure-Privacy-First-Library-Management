/**
 * Private book reviews (feature F7).
 *
 * These are reading notes, not public ratings: only the author can read them.
 * The book's identity lives inside the ciphertext, so the librarian cannot even
 * see which book a patron wrote about.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys, requirePatron } from '../middleware/auth.js'
import { sealEcc, openEcc, DOMAINS } from '../services/records.js'
import { audit } from '../services/audit.js'

const router = Router()

const MAX_BODY = 2000

async function loadReviews(req) {
  const rows = unwrap(
    await db.from('reviews').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }),
    'review list',
  )

  const items = []
  for (const row of rows) {
    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.review)
    if (opened.integrity === 'tampered' && !row.tampered) {
      await db.from('reviews').update({ tampered: true }).eq('id', row.id)
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'integrity_failure',
        outcome: 'warning',
        detail: `review ${row.id} failed HMAC verification`,
      })
    }
    items.push({
      id: row.id,
      bookId: opened.data?.bookId ?? null,
      bookTitle: opened.data?.title ?? null,
      author: opened.data?.author ?? null,
      rating: opened.data?.rating ?? null,
      body: opened.data?.body ?? null,
      writtenAt: opened.data?.writtenAt ?? row.created_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      keyVersion: row.key_version,
      integrity: opened.integrity,
      raw: { ciphertext: row.ciphertext, hmacTag: row.hmac_tag },
    })
  }
  return items
}

/** Books this patron has returned - the only ones they may review. */
async function returnedBooks(req) {
  const rows = unwrap(
    await db.from('checkouts').select('*').eq('user_id', req.user.id).eq('status', 'returned'),
    'returned list',
  )
  const books = new Map()
  for (const row of rows) {
    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.checkout)
    if (opened.integrity !== 'ok') continue
    books.set(opened.data.bookId, {
      id: opened.data.bookId,
      title: opened.data.title,
      author: opened.data.author,
      returnedAt: opened.data.returnedAt ?? row.returned_at,
    })
  }
  return books
}

router.get(
  '/',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const reviews = await loadReviews(req)
    res.json({ reviews, count: reviews.length })
  }),
)

router.get(
  '/eligible',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const books = await returnedBooks(req)
    const reviews = await loadReviews(req)
    const reviewed = new Set(reviews.map(r => r.bookId))
    res.json({ books: [...books.values()].filter(b => !reviewed.has(b.id)) })
  }),
)

function validate(body, { partial = false } = {}) {
  const errors = []
  const out = {}
  if ('rating' in body || !partial) {
    const rating = Number.parseInt(body.rating, 10)
    if (!Number.isFinite(rating) || rating < 1 || rating > 5) errors.push('Rating must be between 1 and 5.')
    else out.rating = rating
  }
  if ('body' in body || !partial) {
    const text = String(body.body ?? '').trim()
    if (!text) errors.push('Write something before saving.')
    if (text.length > MAX_BODY) errors.push(`Reviews are limited to ${MAX_BODY} characters.`)
    out.body = text
  }
  return { errors, out }
}

router.post(
  '/',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const bookId = String(req.body?.bookId ?? '')
    if (!bookId) throw httpError(400, 'VALIDATION_ERROR', 'A bookId is required.')

    const { errors, out } = validate(req.body ?? {})
    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))

    const books = await returnedBooks(req)
    const book = books.get(bookId)
    if (!book) throw httpError(403, 'NOT_ELIGIBLE', 'You can only review a book you have borrowed and returned.')

    const existing = (await loadReviews(req)).find(r => r.bookId === bookId)
    if (existing) throw httpError(409, 'ALREADY_REVIEWED', 'You have already written a note about this book.')

    const record = {
      bookId,
      title: book.title,
      author: book.author,
      rating: out.rating,
      body: out.body,
      writtenAt: new Date().toISOString(),
    }
    const sealed = sealEcc(req.keys.ecc.pub, req.keys.macKey, record, DOMAINS.review)

    const row = unwrap(
      await db
        .from('reviews')
        .insert({
          user_id: req.user.id,
          ciphertext: sealed.ciphertext,
          hmac_tag: sealed.hmac_tag,
          key_version: req.keys.keyVersion,
        })
        .select()
        .single(),
      'review insert',
    )

    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'review_create', detail: `review ${row.id} sealed` })
    res.status(201).json({ review: { id: row.id, ...record, integrity: 'ok' } })
  }),
)

router.patch(
  '/:id',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    // Scoped by user_id, and a miss is reported as 404 rather than 403 so the
    // endpoint does not confirm that somebody else's review exists.
    const row = unwrap(
      await db.from('reviews').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle(),
      'review read',
    )
    if (!row) throw httpError(404, 'NOT_FOUND', 'No such review.')

    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.review)
    if (opened.integrity !== 'ok') throw httpError(409, 'INTEGRITY_FAILURE', 'This review failed its integrity check and cannot be edited.')

    const { errors, out } = validate(req.body ?? {}, { partial: true })
    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))

    const record = { ...opened.data, ...out, editedAt: new Date().toISOString() }
    const sealed = sealEcc(req.keys.ecc.pub, req.keys.macKey, record, DOMAINS.review)

    unwrap(
      await db
        .from('reviews')
        .update({
          ciphertext: sealed.ciphertext,
          hmac_tag: sealed.hmac_tag,
          key_version: req.keys.keyVersion,
          updated_at: new Date().toISOString(),
        })
        .eq('id', row.id)
        .select('id')
        .single(),
      'review update',
    )

    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'review_update', detail: `review ${row.id} re-sealed` })
    res.json({ review: { id: row.id, ...record, integrity: 'ok' } })
  }),
)

router.delete(
  '/:id',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const row = unwrap(
      await db.from('reviews').select('id').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle(),
      'review read',
    )
    if (!row) throw httpError(404, 'NOT_FOUND', 'No such review.')
    unwrap(await db.from('reviews').delete().eq('id', row.id).select('id').maybeSingle(), 'review delete')
    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'review_delete', detail: `review ${row.id} deleted` })
    res.json({ ok: true })
  }),
)

export default router
