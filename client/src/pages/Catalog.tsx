import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError, type Book } from '../lib/api'
import { Badge, Card, EmptyState, ErrorNote, Input, PageHeader, SearchIcon, Select, Spinner } from '../components/ui'
import { cx } from '../lib/format'

export function BookSpine({ hue, className }: { hue: number; className?: string }) {
  return (
    <div
      className={cx('relative overflow-hidden rounded-lg', className)}
      style={{
        background: `linear-gradient(150deg, hsl(${hue} 55% 24%), hsl(${(hue + 40) % 360} 45% 12%))`,
      }}
      aria-hidden="true"
    >
      <div className="absolute inset-y-0 left-2.5 w-px bg-white/15" />
      <div className="absolute inset-y-0 left-4 w-px bg-white/8" />
    </div>
  )
}

export default function Catalog() {
  const [books, setBooks] = useState<Book[]>([])
  const [genres, setGenres] = useState<{ genre: string; count: number }[]>([])
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [genre, setGenre] = useState('')
  const [availability, setAvailability] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query.trim()), 250)
    return () => clearTimeout(timer)
  }, [query])

  useEffect(() => {
    api.books
      .genres()
      .then(r => setGenres(r.genres))
      .catch(() => setGenres([]))
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.books
      .list({ q: debounced || undefined, genre: genre || undefined, availability })
      .then(r => {
        if (!cancelled) {
          setBooks(r.books)
          setError(null)
        }
      })
      .catch(err => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Could not load the catalog.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [debounced, genre, availability])

  const totalAvailable = useMemo(() => books.reduce((n, b) => n + b.availableCopies, 0), [books])

  return (
    <>
      <PageHeader
        title="Catalog"
        subtitle="The catalogue is the one thing in BookVault that is not sensitive, so it is stored in plaintext and fully searchable. What you borrow from it is not."
      />

      <div className="mb-5 flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint">
            <SearchIcon size={15} />
          </span>
          <Input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search by title, author or genre"
            className="pl-9"
            aria-label="Search the catalog"
          />
        </div>
        <Select value={availability} onChange={e => setAvailability(e.target.value)} className="sm:w-44" aria-label="Availability">
          <option value="all">All books</option>
          <option value="available">Available now</option>
        </Select>
      </div>

      {genres.length > 0 && (
        <div className="mb-5 flex flex-wrap gap-2">
          <button
            onClick={() => setGenre('')}
            className={cx(
              'rounded-full border px-3 py-1 text-xs transition-colors',
              genre === '' ? 'border-accent/40 bg-accent/12 text-accent' : 'border-line text-muted hover:bg-surface-2',
            )}
          >
            All genres
          </button>
          {genres.map(g => (
            <button
              key={g.genre}
              onClick={() => setGenre(current => (current === g.genre ? '' : g.genre))}
              className={cx(
                'rounded-full border px-3 py-1 text-xs transition-colors',
                genre === g.genre ? 'border-accent/40 bg-accent/12 text-accent' : 'border-line text-muted hover:bg-surface-2',
              )}
            >
              {g.genre} <span className="text-faint">{g.count}</span>
            </button>
          ))}
        </div>
      )}

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {loading ? (
        <div className="flex justify-center py-20 text-muted">
          <Spinner size={22} />
        </div>
      ) : books.length === 0 ? (
        <EmptyState
          title="No books match those filters"
          hint="Try a different search term, or clear the genre and availability filters."
        />
      ) : (
        <>
          <div className="mb-3 text-xs text-faint">
            {books.length} {books.length === 1 ? 'title' : 'titles'} · {totalAvailable} copies on the shelf
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {books.map(book => (
              <Link
                key={book.id}
                to={`/catalog/${book.id}`}
                className="group rounded-xl2 border border-line bg-surface p-4 transition-colors hover:border-accent/35 hover:bg-surface-2"
              >
                <div className="flex gap-3.5">
                  <BookSpine hue={book.coverHue} className="h-24 w-16 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <h3 className="line-clamp-2 text-sm font-semibold leading-snug text-slate-100 transition-colors group-hover:text-accent">
                      {book.title}
                    </h3>
                    <p className="mt-1 line-clamp-1 text-xs text-muted">{book.author}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <Badge tone="neutral">{book.genre}</Badge>
                      {book.publishedYear && <span className="text-[11px] text-faint">{book.publishedYear}</span>}
                    </div>
                    <div className="mt-2.5">
                      {book.availableCopies > 0 ? (
                        <Badge tone="accent">
                          {book.availableCopies} of {book.totalCopies} available
                        </Badge>
                      ) : (
                        <Badge tone="warn">All copies on loan</Badge>
                      )}
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </>
      )}
    </>
  )
}
