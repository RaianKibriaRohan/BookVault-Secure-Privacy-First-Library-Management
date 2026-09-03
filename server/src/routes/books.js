/**
 * Book catalog (feature F2 for patrons, A1 for the librarian).
 *
 * Catalog data is the one class of data in BookVault that is NOT sensitive:
 * which books the library owns is public information. It is therefore stored in
 * plaintext, which is what makes searching and sorting possible. Everything
 * that reveals a *patron's* relationship to a book is encrypted elsewhere.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireAdmin } from '../middleware/auth.js'
import { audit } from '../services/audit.js'

const router = Router()

const shape = row => ({
  id: row.id,
  title: row.title,
  author: row.author,
  isbn: row.isbn,
  genre: row.genre,
  description: row.description,
  publishedYear: row.published_year,
  totalCopies: row.total_copies,
  availableCopies: row.available_copies,
  coverHue: row.cover_hue,
  createdAt: row.created_at,
})

router.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const q = String(req.query.q ?? '').trim()
    const genre = String(req.query.genre ?? '').trim()
    const availability = String(req.query.availability ?? 'all')

    let query = db.from('books').select('*').order('title', { ascending: true })
    if (q) {
      const safe = q.replace(/[,%()]/g, ' ')
      query = query.or(`title.ilike.%${safe}%,author.ilike.%${safe}%,genre.ilike.%${safe}%`)
    }
    if (genre) query = query.eq('genre', genre)
    if (availability === 'available') query = query.gt('available_copies', 0)

    const rows = unwrap(await query, 'book list')
    res.json({ books: rows.map(shape), count: rows.length })
  }),
)

router.get(
  '/genres',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = unwrap(await db.from('books').select('genre'), 'genre list')
    const counts = new Map()
    for (const row of rows) counts.set(row.genre, (counts.get(row.genre) ?? 0) + 1)
    res.json({
      genres: [...counts.entries()]
        .map(([genre, count]) => ({ genre, count }))
        .sort((a, b) => a.genre.localeCompare(b.genre)),
    })
  }),
)

router.get(
  '/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const row = unwrap(await db.from('books').select('*').eq('id', req.params.id).maybeSingle(), 'book read')
    if (!row) throw httpError(404, 'NOT_FOUND', 'That book is not in the catalog.')
    res.json({ book: shape(row) })
  }),
)

// --- Admin inventory management (A1) ---------------------------------------

function validateBook(body, { partial = false } = {}) {
  const errors = []
  const out = {}
  const str = (key, column, max, required) => {
    if (!(key in body)) {
      if (!partial && required) errors.push(`${key} is required.`)
      return
    }
    const value = String(body[key] ?? '').trim()
    if (required && !value) errors.push(`${key} cannot be empty.`)
    if (value.length > max) errors.push(`${key} is too long (max ${max}).`)
    out[column] = value
  }

  str('title', 'title', 200, true)
  str('author', 'author', 200, true)
  str('isbn', 'isbn', 32, true)
  str('genre', 'genre', 80, true)
  str('description', 'description', 2000, false)

  if ('publishedYear' in body) {
    const year = Number.parseInt(body.publishedYear, 10)
    if (Number.isFinite(year) && (year < 0 || year > 2100)) errors.push('publishedYear is out of range.')
    out.published_year = Number.isFinite(year) ? year : null
  }
  if ('coverHue' in body) {
    const hue = Number.parseInt(body.coverHue, 10)
    out.cover_hue = Number.isFinite(hue) ? ((hue % 360) + 360) % 360 : 210
  }
  if ('totalCopies' in body) {
    const total = Number.parseInt(body.totalCopies, 10)
    if (!Number.isFinite(total) || total < 0) errors.push('totalCopies must be zero or more.')
    else out.total_copies = total
  }
  return { errors, out }
}

router.post(
  '/',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const { errors, out } = validateBook(req.body ?? {})
    if (!('total_copies' in out)) out.total_copies = 1
    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))

    const clash = unwrap(await db.from('books').select('id').eq('isbn', out.isbn).maybeSingle(), 'isbn check')
    if (clash) throw httpError(409, 'ISBN_TAKEN', 'A book with that ISBN already exists.')

    out.available_copies = out.total_copies
    const row = unwrap(await db.from('books').insert(out).select().single(), 'book insert')
    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'book_create', detail: row.title })
    res.status(201).json({ book: shape(row) })
  }),
)

router.patch(
  '/:id',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const existing = unwrap(await db.from('books').select('*').eq('id', req.params.id).maybeSingle(), 'book read')
    if (!existing) throw httpError(404, 'NOT_FOUND', 'That book is not in the catalog.')

    const { errors, out } = validateBook(req.body ?? {}, { partial: true })
    if (errors.length) throw httpError(400, 'VALIDATION_ERROR', errors.join(' '))

    if (out.isbn && out.isbn !== existing.isbn) {
      const clash = unwrap(await db.from('books').select('id').eq('isbn', out.isbn).maybeSingle(), 'isbn check')
      if (clash) throw httpError(409, 'ISBN_TAKEN', 'A book with that ISBN already exists.')
    }

    // Changing the total shifts availability by the same delta, so copies that
    // are currently on loan are not conjured back into the shelf count.
    if ('total_copies' in out) {
      const delta = out.total_copies - existing.total_copies
      out.available_copies = Math.max(0, Math.min(out.total_copies, existing.available_copies + delta))
    }
    out.updated_at = new Date().toISOString()

    const row = unwrap(await db.from('books').update(out).eq('id', req.params.id).select().single(), 'book update')
    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'book_update', detail: row.title })
    res.json({ book: shape(row) })
  }),
)

router.delete(
  '/:id',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const existing = unwrap(await db.from('books').select('*').eq('id', req.params.id).maybeSingle(), 'book read')
    if (!existing) throw httpError(404, 'NOT_FOUND', 'That book is not in the catalog.')
    if (existing.available_copies < existing.total_copies) {
      throw httpError(409, 'BOOK_ON_LOAN', 'Copies of this book are currently on loan and must be returned first.')
    }
    unwrap(await db.from('books').delete().eq('id', req.params.id).select('id').maybeSingle(), 'book delete')
    await audit(req, { userId: req.user.id, username: req.user.username, eventType: 'book_delete', detail: existing.title })
    res.json({ ok: true })
  }),
)

export default router
