/**
 * Borrowing and returning (features F3, F4, F6).
 *
 * A checkout record is ECIES-encrypted under the patron's own ECC public key
 * and HMAC-tagged before it is written. The database keeps only two plaintext
 * mirrors - due_date and status - so the library can enforce due dates and
 * count loans without ever decrypting anything.
 *
 * Crucially, book_id is NOT mirrored. The librarian can see that a patron has
 * a loan due on the 14th; they cannot see which book it is. The cost is that
 * returning a book requires the patron's own session to decrypt the record
 * first, which is exactly the trade this project is arguing for.
 */
import { Router } from 'express'
import config from '../config.js'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys, requirePatron } from '../middleware/auth.js'
import { sealEcc, openEcc, DOMAINS } from '../services/records.js'
import { computeFine, daysBetween, daysUntilDue, addDays } from '../services/fines.js'
import { audit } from '../services/audit.js'

const router = Router()

/** Decrypts every checkout the caller owns and annotates it with due-date maths. */
async function loadCheckouts(req) {
  const rows = unwrap(
    await db.from('checkouts').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }),
    'checkout list',
  )

  const items = []
  for (const row of rows) {
    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.checkout)

    if (opened.integrity === 'tampered' && !row.tampered) {
      // Persist the finding and shout about it in the audit log.
      await db.from('checkouts').update({ tampered: true }).eq('id', row.id)
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'integrity_failure',
        outcome: 'warning',
        detail: `checkout ${row.id} failed HMAC verification`,
      })
    }

    const overdueDays = row.status === 'active' ? daysBetween(row.due_date) : daysBetween(row.due_date, row.returned_at ?? undefined)
    items.push({
      id: row.id,
      book: opened.data
        ? { id: opened.data.bookId, title: opened.data.title, author: opened.data.author, isbn: opened.data.isbn }
        : null,
      checkoutDate: row.checkout_date,
      dueDate: row.due_date,
      status: row.status,
      returnedAt: row.returned_at,
      daysLeft: daysUntilDue(row.due_date),
      overdueDays,
      projectedFine: row.status === 'active' && overdueDays > 0 ? computeFine(overdueDays) : null,
      keyVersion: row.key_version,
      integrity: opened.integrity,
      raw: { ciphertext: row.ciphertext, hmacTag: row.hmac_tag },
    })
  }
  return { rows, items }
}

router.get(
  '/',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const { items } = await loadCheckouts(req)
    res.json({
      checkouts: items,
      summary: {
        active: items.filter(i => i.status === 'active').length,
        overdue: items.filter(i => i.status === 'active' && i.overdueDays > 0).length,
        returned: items.filter(i => i.status === 'returned').length,
        tampered: items.filter(i => i.integrity !== 'ok').length,
      },
    })
  }),
)

router.post(
  '/',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const bookId = String(req.body?.bookId ?? '')
    if (!bookId) throw httpError(400, 'VALIDATION_ERROR', 'A bookId is required.')

    // F5: unpaid fines block further borrowing.
    const unpaid = unwrap(
      await db.from('fines').select('amount').eq('user_id', req.user.id).eq('status', 'unpaid'),
      'fine check',
    )
    if (unpaid.length) {
      const total = unpaid.reduce((sum, f) => sum + Number(f.amount), 0)
      throw httpError(403, 'FINES_OUTSTANDING', `Clear your outstanding fines (${total} BDT) before borrowing again.`)
    }

    const book = unwrap(await db.from('books').select('*').eq('id', bookId).maybeSingle(), 'book read')
    if (!book) throw httpError(404, 'NOT_FOUND', 'That book is not in the catalog.')
    if (book.available_copies < 1) throw httpError(409, 'NO_COPIES', 'Every copy of this book is currently on loan.')

    // Because book_id is not stored in plaintext, the duplicate check has to
    // decrypt the patron's own active records. Only they can do that.
    const { items } = await loadCheckouts(req)
    if (items.some(i => i.status === 'active' && i.book?.id === bookId)) {
      throw httpError(409, 'ALREADY_BORROWED', 'You already have this book on loan.')
    }

    const checkoutDate = new Date().toISOString().slice(0, 10)
    const dueDate = addDays(config.LOAN_DAYS)

    const record = {
      bookId: book.id,
      title: book.title,
      author: book.author,
      isbn: book.isbn,
      genre: book.genre,
      checkoutDate,
      dueDate,
      status: 'active',
    }
    const sealed = sealEcc(req.keys.ecc.pub, req.keys.macKey, record, DOMAINS.checkout)

    const row = unwrap(
      await db
        .from('checkouts')
        .insert({
          user_id: req.user.id,
          ciphertext: sealed.ciphertext,
          hmac_tag: sealed.hmac_tag,
          key_version: req.keys.keyVersion,
          checkout_date: checkoutDate,
          due_date: dueDate,
          status: 'active',
        })
        .select()
        .single(),
      'checkout insert',
    )

    unwrap(
      await db
        .from('books')
        .update({ available_copies: book.available_copies - 1, updated_at: new Date().toISOString() })
        .eq('id', book.id)
        .select('id')
        .single(),
      'copy decrement',
    )

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'borrow',
      detail: `checkout ${row.id} sealed with ECIES + HMAC, due ${dueDate}`,
    })

    res.status(201).json({
      checkout: { id: row.id, dueDate, checkoutDate, status: 'active', book: { id: book.id, title: book.title, author: book.author } },
      encrypted: { ciphertext: sealed.ciphertext.slice(0, 96) + '...', hmacTag: sealed.hmac_tag },
    })
  }),
)

router.post(
  '/:id/return',
  requireAuth,
  requireKeys,
  requirePatron,
  asyncHandler(async (req, res) => {
    const row = unwrap(
      await db.from('checkouts').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle(),
      'checkout read',
    )
    if (!row) throw httpError(404, 'NOT_FOUND', 'No such checkout.')
    if (row.status === 'returned') throw httpError(409, 'ALREADY_RETURNED', 'That book has already been returned.')

    const opened = openEcc(req.keys.ecc.priv, req.keys.macKey, row, DOMAINS.checkout)
    if (opened.integrity !== 'ok') {
      await db.from('checkouts').update({ tampered: true }).eq('id', row.id)
      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'integrity_failure',
        outcome: 'warning',
        detail: `return blocked: checkout ${row.id} failed integrity verification`,
      })
      throw httpError(409, 'INTEGRITY_FAILURE', 'This record failed its integrity check and cannot be processed. Contact the librarian.')
    }

    const returnedAt = new Date().toISOString()
    const daysOverdue = daysBetween(row.due_date, returnedAt)

    // Re-seal the record with its new status and a fresh HMAC tag.
    const updated = { ...opened.data, status: 'returned', returnedAt }
    const sealed = sealEcc(req.keys.ecc.pub, req.keys.macKey, updated, DOMAINS.checkout)

    unwrap(
      await db
        .from('checkouts')
        .update({
          ciphertext: sealed.ciphertext,
          hmac_tag: sealed.hmac_tag,
          key_version: req.keys.keyVersion,
          status: 'returned',
          returned_at: returnedAt,
        })
        .eq('id', row.id)
        .select('id')
        .single(),
      'checkout update',
    )

    // Put the copy back on the shelf.
    const book = unwrap(await db.from('books').select('*').eq('id', opened.data.bookId).maybeSingle(), 'book read')
    if (book) {
      await db
        .from('books')
        .update({
          available_copies: Math.min(book.total_copies, book.available_copies + 1),
          updated_at: new Date().toISOString(),
        })
        .eq('id', book.id)
    }

    let fine = null
    if (daysOverdue > 0) {
      const computed = computeFine(daysOverdue)
      const fineRecord = {
        checkoutId: row.id,
        bookId: opened.data.bookId,
        title: opened.data.title,
        author: opened.data.author,
        dueDate: row.due_date,
        returnedAt,
        daysOverdue,
        breakdown: computed.breakdown,
        amount: computed.amount,
        replacementNotice: computed.replacementNotice,
      }
      const sealedFine = sealEcc(req.keys.ecc.pub, req.keys.macKey, fineRecord, DOMAINS.fine)

      const fineRow = unwrap(
        await db
          .from('fines')
          .insert({
            user_id: req.user.id,
            checkout_id: row.id,
            ciphertext: sealedFine.ciphertext,
            hmac_tag: sealedFine.hmac_tag,
            key_version: req.keys.keyVersion,
            amount: computed.amount,
            days_overdue: daysOverdue,
            status: 'unpaid',
            replacement_notice: computed.replacementNotice,
          })
          .select()
          .single(),
        'fine insert',
      )

      fine = { id: fineRow.id, ...computed }

      await audit(req, {
        userId: req.user.id,
        username: req.user.username,
        eventType: 'fine_issued',
        outcome: 'warning',
        detail: `${daysOverdue} days overdue, ${computed.amount} BDT${computed.replacementNotice ? ', replacement notice' : ''}`,
      })
    }

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'return',
      detail: daysOverdue > 0 ? `returned ${daysOverdue} days late` : 'returned on time',
    })

    res.json({ returned: true, daysOverdue, fine })
  }),
)

export default router
