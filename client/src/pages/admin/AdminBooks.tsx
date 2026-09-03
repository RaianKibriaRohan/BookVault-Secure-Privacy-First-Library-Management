import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ApiError, type Book } from '../../lib/api'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Modal,
  PageHeader,
  SearchIcon,
  Spinner,
  Textarea,
  useToast,
} from '../../components/ui'
import { cx } from '../../lib/format'

type SortKey = 'title' | 'author' | 'genre' | 'availableCopies'

const emptyForm = {
  title: '',
  author: '',
  isbn: '',
  genre: '',
  description: '',
  publishedYear: '',
  totalCopies: '1',
  coverHue: '210',
}

export default function AdminBooks() {
  const toast = useToast()
  const [books, setBooks] = useState<Book[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'title', dir: 1 })

  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<Book | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<Book | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api.books.list()
      setBooks(data.books)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load the inventory.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const visible = useMemo(() => {
    const term = query.trim().toLowerCase()
    const filtered = term
      ? books.filter(b =>
          [b.title, b.author, b.genre, b.isbn].some(value => value.toLowerCase().includes(term)),
        )
      : books
    return [...filtered].sort((a, b) => {
      const av = a[sort.key]
      const bv = b[sort.key]
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * sort.dir
      return String(av).localeCompare(String(bv)) * sort.dir
    })
  }, [books, query, sort])

  const openCreate = () => {
    setEditing(null)
    setForm(emptyForm)
    setFormError(null)
    setModalOpen(true)
  }

  const openEdit = (book: Book) => {
    setEditing(book)
    setForm({
      title: book.title,
      author: book.author,
      isbn: book.isbn,
      genre: book.genre,
      description: book.description,
      publishedYear: book.publishedYear ? String(book.publishedYear) : '',
      totalCopies: String(book.totalCopies),
      coverHue: String(book.coverHue),
    })
    setFormError(null)
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setFormError(null)
    const payload = {
      title: form.title.trim(),
      author: form.author.trim(),
      isbn: form.isbn.trim(),
      genre: form.genre.trim(),
      description: form.description.trim(),
      publishedYear: form.publishedYear ? Number(form.publishedYear) : null,
      totalCopies: Number(form.totalCopies),
      coverHue: Number(form.coverHue),
    }
    try {
      if (editing) {
        await api.books.update(editing.id, payload)
        toast.push('Book updated.', 'success')
      } else {
        await api.books.create(payload)
        toast.push('Book added to the catalog.', 'success')
      }
      setModalOpen(false)
      await load()
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'Could not save the book.')
    } finally {
      setSaving(false)
    }
  }

  const remove = async (book: Book) => {
    try {
      await api.books.remove(book.id)
      toast.push(`"${book.title}" removed.`, 'success')
      setConfirmDelete(null)
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not delete the book.', 'error')
      setConfirmDelete(null)
    }
  }

  const toggleSort = (key: SortKey) =>
    setSort(current => ({ key, dir: current.key === key && current.dir === 1 ? -1 : 1 }))

  const ready = form.title.trim() && form.author.trim() && form.isbn.trim() && form.genre.trim()

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  return (
    <>
      <PageHeader
        title="Inventory"
        subtitle="The catalogue is public information and stored in plaintext. Only the librarian can write to it; patrons have read access."
        actions={<Button onClick={openCreate}>Add a book</Button>}
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      <div className="relative mb-4 max-w-sm">
        <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint">
          <SearchIcon size={15} />
        </span>
        <Input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search title, author, genre or ISBN" className="pl-9" />
      </div>

      {visible.length === 0 ? (
        <EmptyState title="No books match" hint="Try a different search term, or add a new title." action={<Button size="sm" onClick={openCreate}>Add a book</Button>} />
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[46rem] text-left text-sm">
            <thead className="border-b border-line text-xs text-faint">
              <tr>
                {([
                  ['title', 'Title'],
                  ['author', 'Author'],
                  ['genre', 'Genre'],
                  ['availableCopies', 'Availability'],
                ] as [SortKey, string][]).map(([key, label]) => (
                  <th key={key} className="px-4 py-2.5 font-medium">
                    <button onClick={() => toggleSort(key)} className="transition-colors hover:text-slate-200">
                      {label} {sort.key === key && (sort.dir === 1 ? '↑' : '↓')}
                    </button>
                  </th>
                ))}
                <th className="px-4 py-2.5 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(book => {
                const onLoan = book.totalCopies - book.availableCopies
                const pct = book.totalCopies ? (book.availableCopies / book.totalCopies) * 100 : 0
                return (
                  <tr key={book.id} className="border-b border-line-soft last:border-0">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className="h-8 w-2 shrink-0 rounded-sm"
                          style={{ background: `hsl(${book.coverHue} 55% 30%)` }}
                          aria-hidden="true"
                        />
                        <div className="min-w-0">
                          <div className="truncate text-slate-200">{book.title}</div>
                          <div className="mono text-[11px] text-faint">{book.isbn}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">{book.author}</td>
                    <td className="px-4 py-3">
                      <Badge tone="neutral">{book.genre}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
                          <div
                            className={cx('h-full rounded-full', pct > 50 ? 'bg-accent' : pct > 0 ? 'bg-warn' : 'bg-danger')}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums text-muted">
                          {book.availableCopies}/{book.totalCopies}
                        </span>
                        {onLoan > 0 && <span className="text-[11px] text-faint">({onLoan} out)</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" variant="ghost" onClick={() => openEdit(book)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="danger" onClick={() => setConfirmDelete(book)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editing ? 'Edit book' : 'Add a book'}
        width="max-w-2xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button loading={saving} disabled={!ready} onClick={save}>
              {editing ? 'Save changes' : 'Add to catalog'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {formError && <ErrorNote>{formError}</ErrorNote>}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Title">
              <Input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} autoFocus />
            </Field>
            <Field label="Author">
              <Input value={form.author} onChange={e => setForm({ ...form, author: e.target.value })} />
            </Field>
            <Field label="ISBN" hint="Must be unique across the catalog.">
              <Input value={form.isbn} onChange={e => setForm({ ...form, isbn: e.target.value })} />
            </Field>
            <Field label="Genre">
              <Input value={form.genre} onChange={e => setForm({ ...form, genre: e.target.value })} />
            </Field>
            <Field label="Published year">
              <Input
                type="number"
                value={form.publishedYear}
                onChange={e => setForm({ ...form, publishedYear: e.target.value })}
              />
            </Field>
            <Field label="Total copies" hint={editing ? 'Changing this adjusts availability by the same amount.' : undefined}>
              <Input
                type="number"
                min={0}
                value={form.totalCopies}
                onChange={e => setForm({ ...form, totalCopies: e.target.value })}
              />
            </Field>
          </div>

          <Field label="Description">
            <Textarea rows={3} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </Field>

          <Field label="Cover hue" hint="Sets the spine colour in the catalog.">
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0}
                max={359}
                value={form.coverHue}
                onChange={e => setForm({ ...form, coverHue: e.target.value })}
                className="flex-1 accent-emerald-400"
              />
              <div
                className="h-10 w-10 shrink-0 rounded-lg border border-line"
                style={{
                  background: `linear-gradient(150deg, hsl(${form.coverHue} 55% 24%), hsl(${(Number(form.coverHue) + 40) % 360} 45% 12%))`,
                }}
                aria-hidden="true"
              />
              <span className="mono w-10 text-right text-xs text-faint">{form.coverHue}</span>
            </div>
          </Field>
        </div>
      </Modal>

      <Modal
        open={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title="Remove this book"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmDelete(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={() => confirmDelete && remove(confirmDelete)}>
              Delete permanently
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">
          <span className="text-slate-100">{confirmDelete?.title}</span> will be removed from the catalog. Books with
          copies currently on loan cannot be deleted.
        </p>
      </Modal>
    </>
  )
}
