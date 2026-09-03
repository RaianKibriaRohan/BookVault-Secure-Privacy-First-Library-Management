import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError, type EligibleBook, type ReviewItem } from '../lib/api'
import { useAuth, useReSignIn } from '../context/AuthContext'
import {
  Badge,
  Button,
  Card,
  Cipher,
  EmptyState,
  ErrorNote,
  Field,
  InfoNote,
  IntegrityBadge,
  KeysLocked,
  Modal,
  PageHeader,
  Select,
  Spinner,
  StarIcon,
  Textarea,
  useToast,
} from '../components/ui'
import { cx, fmtDate } from '../lib/format'

const MAX_BODY = 2000

function StarRating({ value, onChange, size = 16 }: { value: number; onChange?: (v: number) => void; size?: number }) {
  return (
    <div className="flex gap-0.5">
      {[1, 2, 3, 4, 5].map(star => {
        const filled = star <= value
        const content = <StarIcon size={size} filled={filled} />
        if (!onChange) {
          return (
            <span key={star} className={filled ? 'text-warn' : 'text-surface-3'}>
              {content}
            </span>
          )
        }
        return (
          <button
            key={star}
            type="button"
            onClick={() => onChange(star)}
            aria-label={`${star} star${star > 1 ? 's' : ''}`}
            className={cx('rounded transition-colors', filled ? 'text-warn' : 'text-surface-3 hover:text-warn/60')}
          >
            {content}
          </button>
        )
      })}
    </div>
  )
}

export default function Reviews() {
  const { labRoutes } = useAuth()
  const reSignIn = useReSignIn()
  const toast = useToast()

  const [reviews, setReviews] = useState<ReviewItem[]>([])
  const [eligible, setEligible] = useState<EligibleBook[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [locked, setLocked] = useState(false)

  const [composerOpen, setComposerOpen] = useState(false)
  const [editing, setEditing] = useState<ReviewItem | null>(null)
  const [bookId, setBookId] = useState('')
  const [rating, setRating] = useState(5)
  const [body, setBody] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [showCipherFor, setShowCipherFor] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [reviewData, eligibleData] = await Promise.all([api.reviews.list(), api.reviews.eligible()])
      setReviews(reviewData.reviews)
      setEligible(eligibleData.books)
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'KEYS_LOCKED') setLocked(true)
      else setError(err instanceof ApiError ? err.message : 'Could not load your reviews.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const openComposer = () => {
    setEditing(null)
    setBookId(eligible[0]?.id ?? '')
    setRating(5)
    setBody('')
    setFormError(null)
    setComposerOpen(true)
  }

  const openEditor = (review: ReviewItem) => {
    setEditing(review)
    setBookId(review.bookId ?? '')
    setRating(review.rating ?? 5)
    setBody(review.body ?? '')
    setFormError(null)
    setComposerOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setFormError(null)
    try {
      if (editing) {
        await api.reviews.update(editing.id, { rating, body })
        toast.push('Review re-encrypted and re-tagged.', 'success')
      } else {
        await api.reviews.create({ bookId, rating, body })
        toast.push('Review sealed with ECIES and an HMAC tag.', 'success')
      }
      setComposerOpen(false)
      await load()
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'Could not save the review.')
    } finally {
      setSaving(false)
    }
  }

  const remove = async (review: ReviewItem) => {
    try {
      await api.reviews.remove(review.id)
      toast.push('Review deleted.', 'success')
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not delete the review.', 'error')
    }
  }

  const tamper = async (id: string) => {
    try {
      await api.lab.tamper('reviews', id)
      toast.push('Ciphertext altered in the database — the MAC will now fail.', 'error')
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Tamper simulation failed.', 'error')
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  if (locked) return <KeysLocked onSignOut={reSignIn} />

  return (
    <>
      <PageHeader
        title="Private reviews"
        subtitle="Reading notes only you can read. Each one is ECIES-encrypted and HMAC-tagged; even the book it refers to lives inside the ciphertext, so the librarian cannot tell what you wrote about."
        actions={
          <Button onClick={openComposer} disabled={eligible.length === 0}>
            Write a review
          </Button>
        }
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {eligible.length === 0 && reviews.length === 0 && (
        <EmptyState
          title="Nothing to review yet"
          hint="You can write a private note about a book once you have borrowed and returned it."
          action={
            <Link to="/catalog">
              <Button size="sm">Browse the catalog</Button>
            </Link>
          }
        />
      )}

      {eligible.length > 0 && (
        <InfoNote className="mb-5" tone="accent">
          {eligible.length} {eligible.length === 1 ? 'book is' : 'books are'} waiting for a note:{' '}
          {eligible.slice(0, 3).map(b => b.title).join(', ')}
          {eligible.length > 3 ? ` and ${eligible.length - 3} more` : ''}.
        </InfoNote>
      )}

      <div className="space-y-3">
        {reviews.map(review => (
          <Card key={review.id} className={cx('p-4', review.integrity !== 'ok' && 'border-danger/40 bg-danger/5')}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">
                    {review.bookTitle ?? <span className="text-danger">Review could not be opened</span>}
                  </h3>
                  <IntegrityBadge integrity={review.integrity} />
                </div>
                {review.author && <p className="mt-0.5 text-xs text-muted">{review.author}</p>}
                {review.rating !== null && (
                  <div className="mt-2">
                    <StarRating value={review.rating} />
                  </div>
                )}
              </div>
              <div className="flex shrink-0 flex-wrap gap-2">
                {review.integrity === 'ok' && (
                  <Button size="sm" variant="ghost" onClick={() => openEditor(review)}>
                    Edit
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => setShowCipherFor(showCipherFor === review.id ? null : review.id)}>
                  {showCipherFor === review.id ? 'Hide stored row' : 'Stored row'}
                </Button>
                {labRoutes && review.integrity === 'ok' && (
                  <Button size="sm" variant="danger" onClick={() => tamper(review.id)}>
                    Simulate tampering
                  </Button>
                )}
                <Button size="sm" variant="danger" onClick={() => remove(review)}>
                  Delete
                </Button>
              </div>
            </div>

            {review.integrity === 'tampered' ? (
              <ErrorNote className="mt-3">
                The stored ciphertext no longer matches its HMAC tag. Decryption was refused rather than returning
                content an attacker may have influenced.
              </ErrorNote>
            ) : (
              review.body && <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-muted">{review.body}</p>
            )}

            <div className="mt-3 flex flex-wrap gap-2 text-xs text-faint">
              <span>Written {fmtDate(review.writtenAt, true)}</span>
              {review.updatedAt !== review.createdAt && <span>· edited {fmtDate(review.updatedAt, true)}</span>}
              <span>· key v{review.keyVersion}</span>
            </div>

            {showCipherFor === review.id && (
              <div className="mt-3 space-y-2">
                <Cipher label="ciphertext as stored" value={review.raw.ciphertext} />
                <Cipher label="hmac_tag" value={review.raw.hmacTag} />
              </div>
            )}
          </Card>
        ))}
      </div>

      <Modal
        open={composerOpen}
        onClose={() => setComposerOpen(false)}
        title={editing ? 'Edit private review' : 'Write a private review'}
        footer={
          <>
            <Button variant="ghost" onClick={() => setComposerOpen(false)}>
              Cancel
            </Button>
            <Button loading={saving} disabled={!body.trim() || (!editing && !bookId)} onClick={save}>
              {editing ? 'Save and re-encrypt' : 'Encrypt and save'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {formError && <ErrorNote>{formError}</ErrorNote>}

          {editing ? (
            <div className="rounded-lg border border-line bg-ink/50 px-3 py-2 text-sm text-slate-200">{editing.bookTitle}</div>
          ) : (
            <Field label="Book" hint="Only books you have borrowed and returned can be reviewed.">
              <Select value={bookId} onChange={e => setBookId(e.target.value)}>
                {eligible.map(book => (
                  <option key={book.id} value={book.id}>
                    {book.title} — {book.author}
                  </option>
                ))}
              </Select>
            </Field>
          )}

          <div>
            <span className="mb-1.5 block text-xs font-medium text-muted">Rating</span>
            <StarRating value={rating} onChange={setRating} size={22} />
          </div>

          <Field label="Your note" hint={`${body.length} / ${MAX_BODY} characters`}>
            <Textarea rows={6} maxLength={MAX_BODY} value={body} onChange={e => setBody(e.target.value)} placeholder="What did you make of it?" />
          </Field>

          <InfoNote tone="accent">
            This text is encrypted with ECIES over secp256k1 before it is stored, and tagged with HMAC-SHA256. Only your
            private key can open it.
          </InfoNote>
        </div>
      </Modal>

      {reviews.length > 0 && (
        <div className="mt-6 flex items-center gap-2 text-xs text-faint">
          <Badge tone="neutral">{reviews.length} private notes</Badge>
          <span>All encrypted at rest with your secp256k1 key.</span>
        </div>
      )}
    </>
  )
}
