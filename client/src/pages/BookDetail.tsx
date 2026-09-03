import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, ApiError, type Book } from '../lib/api'
import { useAuth } from '../context/AuthContext'
import { BookSpine } from './Catalog'
import { Badge, Button, Card, ErrorNote, InfoNote, LockIcon, PageHeader, Spinner, useToast } from '../components/ui'

const pipeline = [
  'A record is built in memory: book id, title, author, ISBN, borrow date, due date.',
  'It is encrypted with ECIES — a fresh ephemeral secp256k1 key, ECDH against your public key, then a derived keystream.',
  'An HMAC-SHA256 tag is computed over the ciphertext with your own MAC key, under a checkout-specific domain string.',
  'Only the ciphertext, the tag, the due date and the status reach the database. The book id is never stored in the clear.',
]

export default function BookDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const toast = useToast()

  const [book, setBook] = useState<Book | null>(null)
  const [loading, setLoading] = useState(true)
  const [borrowing, setBorrowing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [errorCode, setErrorCode] = useState<string | null>(null)

  const load = () => {
    if (!id) return
    setLoading(true)
    api.books
      .get(id)
      .then(r => {
        setBook(r.book)
        setError(null)
      })
      .catch(err => setError(err instanceof ApiError ? err.message : 'Could not load this book.'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [id])

  const borrow = async () => {
    if (!id) return
    setBorrowing(true)
    setError(null)
    setErrorCode(null)
    try {
      await api.checkouts.borrow(id)
      toast.push('Borrowed — the record is encrypted and in your vault.', 'success')
      navigate('/vault')
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
        setErrorCode(err.code)
      } else {
        setError('Could not borrow this book.')
      }
    } finally {
      setBorrowing(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  if (!book) {
    return (
      <>
        <ErrorNote>{error ?? 'That book is not in the catalog.'}</ErrorNote>
        <div className="mt-4">
          <Link to="/catalog">
            <Button variant="ghost">Back to the catalog</Button>
          </Link>
        </div>
      </>
    )
  }

  const isAdmin = user?.role === 'admin'

  return (
    <>
      <Link to="/catalog" className="mb-4 inline-flex items-center gap-1.5 text-xs text-muted transition-colors hover:text-slate-200">
        ← Back to the catalog
      </Link>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div>
          <Card className="p-6">
            <div className="flex flex-col gap-5 sm:flex-row">
              <BookSpine hue={book.coverHue} className="h-44 w-28 shrink-0 self-start" />
              <div className="min-w-0 flex-1">
                <h1 className="text-xl font-semibold leading-snug tracking-tight text-slate-50">{book.title}</h1>
                <p className="mt-1 text-sm text-muted">{book.author}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Badge tone="neutral">{book.genre}</Badge>
                  {book.publishedYear && <Badge tone="neutral">{book.publishedYear}</Badge>}
                  {book.availableCopies > 0 ? (
                    <Badge tone="accent">
                      {book.availableCopies} of {book.totalCopies} available
                    </Badge>
                  ) : (
                    <Badge tone="warn">All {book.totalCopies} copies on loan</Badge>
                  )}
                </div>
                <p className="mt-4 text-sm leading-relaxed text-muted">{book.description}</p>
                <dl className="mt-4 grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
                  <div className="flex justify-between border-b border-line-soft pb-1.5">
                    <dt className="text-faint">ISBN</dt>
                    <dd className="mono text-slate-300">{book.isbn}</dd>
                  </div>
                  <div className="flex justify-between border-b border-line-soft pb-1.5">
                    <dt className="text-faint">Loan period</dt>
                    <dd className="text-slate-300">14 days</dd>
                  </div>
                </dl>
              </div>
            </div>

            {error && (
              <div className="mt-5">
                <ErrorNote>{error}</ErrorNote>
                {errorCode === 'FINES_OUTSTANDING' && (
                  <div className="mt-2">
                    <Link to="/vault">
                      <Button size="sm" variant="warn">
                        Go to my fines
                      </Button>
                    </Link>
                  </div>
                )}
                {errorCode === 'ALREADY_BORROWED' && (
                  <div className="mt-2">
                    <Link to="/vault">
                      <Button size="sm" variant="ghost">
                        View it in my vault
                      </Button>
                    </Link>
                  </div>
                )}
              </div>
            )}

            <div className="mt-6 flex flex-wrap gap-2">
              {isAdmin ? (
                <>
                  <InfoNote className="w-full">
                    You are signed in as the Head Librarian. Borrowing is a patron action — administrators manage the
                    inventory instead.
                  </InfoNote>
                  <Link to="/admin/books">
                    <Button variant="ghost">Edit in the admin console</Button>
                  </Link>
                </>
              ) : (
                <Button onClick={borrow} loading={borrowing} disabled={book.availableCopies < 1}>
                  {book.availableCopies < 1 ? 'No copies available' : 'Borrow this book'}
                </Button>
              )}
            </div>
          </Card>
        </div>

        <Card className="h-fit p-5">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-accent">
            <LockIcon size={13} /> What happens when you borrow
          </div>
          <ol className="space-y-3">
            {pipeline.map((step, index) => (
              <li key={index} className="flex gap-3 text-xs leading-relaxed text-muted">
                <span className="mono mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-line text-[10px] text-faint">
                  {index + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
          <p className="mt-4 border-t border-line pt-3 text-xs leading-relaxed text-faint">
            The librarian can see that a loan exists and when it is due — never which book it is.
          </p>
        </Card>
      </div>
    </>
  )
}
