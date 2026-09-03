import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, type AdminFine, type FineSummary } from '../../lib/api'
import { Badge, Card, Cipher, EmptyState, ErrorNote, InfoNote, PageHeader, Select, Spinner, Stat } from '../../components/ui'
import { fmtBDT, fmtDate } from '../../lib/format'

type SortKey = 'createdAt' | 'amount' | 'daysOverdue' | 'username'

export default function AdminFines() {
  const [fines, setFines] = useState<AdminFine[]>([])
  const [summary, setSummary] = useState<FineSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState('all')
  const [sort, setSort] = useState<SortKey>('createdAt')
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    api.admin
      .fines()
      .then(data => {
        setFines(data.fines)
        setSummary(data.summary)
        setError(null)
      })
      .catch(err => setError(err instanceof ApiError ? err.message : 'Could not load the fine dashboard.'))
      .finally(() => setLoading(false))
  }, [])

  const visible = useMemo(() => {
    const filtered = status === 'all' ? fines : fines.filter(f => f.status === status)
    return [...filtered].sort((a, b) => {
      if (sort === 'username') return a.username.localeCompare(b.username)
      if (sort === 'amount') return b.amount - a.amount
      if (sort === 'daysOverdue') return b.daysOverdue - a.daysOverdue
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    })
  }, [fines, status, sort])

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
        title="Fines"
        subtitle="Amounts and payment status are plaintext because the library needs them to operate. What the fine was for stays encrypted."
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {summary && (
        <div className="mb-5 grid gap-3 sm:grid-cols-3">
          <Stat label="Outstanding" value={fmtBDT(summary.outstanding)} tone={summary.outstanding ? 'warn' : 'default'} hint={`${summary.unpaidCount} unpaid`} />
          <Stat label="Collected" value={fmtBDT(summary.paid)} tone="accent" />
          <Stat label="Total issued" value={fmtBDT(summary.outstanding + summary.paid)} hint={`${fines.length} records`} />
        </div>
      )}

      <div className="mb-4 flex flex-wrap gap-3">
        <Select value={status} onChange={e => setStatus(e.target.value)} className="w-40" aria-label="Filter by status">
          <option value="all">All fines</option>
          <option value="unpaid">Unpaid only</option>
          <option value="paid">Paid only</option>
        </Select>
        <Select value={sort} onChange={e => setSort(e.target.value as SortKey)} className="w-48" aria-label="Sort by">
          <option value="createdAt">Newest first</option>
          <option value="amount">Largest amount</option>
          <option value="daysOverdue">Most days overdue</option>
          <option value="username">Patron name</option>
        </Select>
      </div>

      {visible.length === 0 ? (
        <EmptyState title="No fines to show" hint="Fines are created automatically when a book is returned late." />
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[48rem] text-left text-sm">
            <thead className="border-b border-line text-xs text-faint">
              <tr>
                <th className="px-4 py-2.5 font-medium">Patron</th>
                <th className="px-4 py-2.5 font-medium">Amount</th>
                <th className="px-4 py-2.5 font-medium">Overdue</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Issued</th>
                <th className="px-4 py-2.5 font-medium">Record body</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(fine => (
                <>
                  <tr key={fine.id} className="border-b border-line-soft last:border-0">
                    <td className="px-4 py-3">
                      <div className="text-slate-200">{fine.username}</div>
                      {fine.userStatus === 'suspended' && <Badge tone="danger">suspended</Badge>}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-warn">{fmtBDT(fine.amount)}</td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {fine.daysOverdue} days
                      {fine.replacementNotice && (
                        <div>
                          <Badge tone="danger">replacement notice</Badge>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge tone={fine.status === 'paid' ? 'accent' : 'warn'}>{fine.status}</Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {fmtDate(fine.createdAt)}
                      {fine.paidAt && <div className="text-[11px] text-faint">paid {fmtDate(fine.paidAt)}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setExpanded(expanded === fine.id ? null : fine.id)}
                        className="mono text-[11px] text-accent/60 transition-colors hover:text-accent"
                      >
                        {expanded === fine.id ? 'hide ciphertext' : `${fine.ciphertext.slice(0, 20)}…`}
                      </button>
                    </td>
                  </tr>
                  {expanded === fine.id && (
                    <tr key={`${fine.id}-cipher`} className="border-b border-line-soft bg-ink/40">
                      <td colSpan={6} className="px-4 py-3">
                        <div className="space-y-2">
                          <Cipher label="fines.ciphertext" value={fine.ciphertext} />
                          <Cipher label="fines.hmac_tag" value={fine.hmacTag} />
                          <p className="text-[11px] text-faint">
                            This is the whole record body: which book, the tier breakdown, the dates. It is ECIES
                            ciphertext under the patron&apos;s key — unreadable from this console.
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <InfoNote className="mt-5" tone="warn">
        Fine tiers: days 1–7 at 5 BDT/day, days 8–14 at 10 BDT/day, day 15 onward at 20 BDT/day plus a book replacement
        notice. Unpaid fines block further borrowing until they are cleared.
      </InfoNote>
    </>
  )
}
