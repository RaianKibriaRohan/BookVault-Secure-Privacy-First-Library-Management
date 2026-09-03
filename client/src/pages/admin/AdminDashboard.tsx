import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError, type AdminStats, type AuditEntry, type EncryptedRow, type EncryptedTable } from '../../lib/api'
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  LockIcon,
  PageHeader,
  Spinner,
  Stat,
} from '../../components/ui'
import { cx, fmtBDT, humanEvent, relativeTime } from '../../lib/format'

const TABLES: { key: EncryptedTable; label: string; column: string }[] = [
  { key: 'checkouts', label: 'Checkout records', column: 'ciphertext' },
  { key: 'reviews', label: 'Private reviews', column: 'ciphertext' },
  { key: 'fines', label: 'Fine records', column: 'ciphertext' },
  { key: 'chat_messages', label: 'Chat messages', column: 'body_for_recipient' },
]

export default function AdminDashboard() {
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [events, setEvents] = useState<AuditEntry[]>([])
  const [table, setTable] = useState<EncryptedTable>('checkouts')
  const [rows, setRows] = useState<EncryptedRow[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingRows, setLoadingRows] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([api.admin.stats(), api.admin.audit({ limit: '8' })])
      .then(([statsData, auditData]) => {
        setStats(statsData)
        setEvents(auditData.events)
        setError(null)
      })
      .catch(err => setError(err instanceof ApiError ? err.message : 'Could not load the dashboard.'))
      .finally(() => setLoading(false))
  }, [])

  const loadRows = useCallback(async (target: EncryptedTable) => {
    setLoadingRows(true)
    try {
      const data = await api.admin.encrypted(target)
      setRows(data.rows)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not read the encrypted table.')
    } finally {
      setLoadingRows(false)
    }
  }, [])

  useEffect(() => {
    void loadRows(table)
  }, [table, loadRows])

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  const activeTable = TABLES.find(t => t.key === table)!

  return (
    <>
      <PageHeader
        title="Librarian overview"
        subtitle="You run the library: the catalogue, accounts, fines and the audit trail. What patrons read, write and say is outside your reach by design."
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {stats && (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Patrons" value={stats.patrons} hint={`${stats.suspended} suspended`} />
            <Stat label="Copies on loan" value={stats.copiesOnLoan} hint={`of ${stats.copies} across ${stats.titles} titles`} />
            <Stat
              label="Overdue loans"
              value={stats.overdueCheckouts}
              tone={stats.overdueCheckouts ? 'warn' : 'default'}
              hint={`${stats.activeCheckouts} active`}
            />
            <Stat
              label="Outstanding fines"
              value={fmtBDT(stats.outstandingFines)}
              tone={stats.outstandingFines ? 'warn' : 'default'}
              hint={`${fmtBDT(stats.paidFines)} collected`}
            />
          </div>

          <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Unread messages" value={stats.unreadMessages} tone={stats.unreadMessages ? 'accent' : 'default'} />
            <Stat label="Audit events (24h)" value={stats.events24h} />
            <Stat label="Failures (24h)" value={stats.failures24h} tone={stats.failures24h ? 'danger' : 'default'} />
            <Stat label="Warnings (24h)" value={stats.warnings24h} tone={stats.warnings24h ? 'warn' : 'default'} />
          </div>
        </>
      )}

      <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
        {/* The proof panel */}
        <Card className="overflow-hidden">
          <div className="border-b border-line px-4 py-3">
            <div className="flex items-center gap-2">
              <LockIcon size={14} />
              <h2 className="text-sm font-semibold text-slate-100">What the librarian can see</h2>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-muted">
              This is a direct read of the encrypted tables — the same view you would get with full SQL access. The
              payload column is ciphertext, and you hold no key that opens it.
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {TABLES.map(t => (
                <button
                  key={t.key}
                  onClick={() => setTable(t.key)}
                  className={cx(
                    'rounded-full border px-3 py-1 text-xs transition-colors',
                    table === t.key ? 'border-accent/40 bg-accent/12 text-accent' : 'border-line text-muted hover:bg-surface-2',
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="max-h-[28rem] overflow-y-auto">
            {loadingRows ? (
              <div className="flex justify-center py-12 text-muted">
                <Spinner size={18} />
              </div>
            ) : rows.length === 0 ? (
              <div className="px-4 py-12 text-center text-sm text-faint">No rows in this table yet.</div>
            ) : (
              rows.map(row => {
                const payload = String(row[activeTable.column] ?? '')
                return (
                  <div key={row.id} className="border-b border-line-soft px-4 py-3 last:border-0">
                    <div className="mb-1.5 flex flex-wrap items-center gap-2 text-[11px] text-faint">
                      <Badge tone="neutral">{row.username ?? 'unknown'}</Badge>
                      {row.recipientName && <span>→ {row.recipientName}</span>}
                      <span>{relativeTime(row.created_at)}</span>
                      {row.key_version !== undefined && <span>· key v{String(row.key_version)}</span>}
                      {'status' in row && <span>· {String(row.status)}</span>}
                      {'amount' in row && <span>· {fmtBDT(Number(row.amount))}</span>}
                    </div>
                    <code className="mono block break-all text-[11px] leading-relaxed text-accent/55">
                      {payload.slice(0, 220)}
                      {payload.length > 220 && '…'}
                    </code>
                    <div className="mt-1 text-[10px] text-faint">
                      {payload.length} hex characters · hmac_tag {String(row.hmac_tag).slice(0, 16)}…
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </Card>

        {/* Recent activity */}
        <Card className="h-fit overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <h2 className="text-sm font-semibold text-slate-100">Recent activity</h2>
            <Link to="/admin/audit" className="text-xs text-accent transition-colors hover:text-accent-dim">
              Full log
            </Link>
          </div>
          <div>
            {events.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-faint">Nothing logged yet.</div>
            ) : (
              events.map(event => (
                <div key={event.id} className="flex items-start gap-3 border-b border-line-soft px-4 py-2.5 last:border-0">
                  <span
                    className={cx(
                      'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                      event.outcome === 'success' ? 'bg-accent' : event.outcome === 'warning' ? 'bg-warn' : 'bg-danger',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-slate-200">
                      {humanEvent(event.eventType)}
                      {event.username && <span className="text-faint"> · {event.username}</span>}
                    </div>
                    {event.detail && <div className="mt-0.5 truncate text-[11px] text-faint">{event.detail}</div>}
                  </div>
                  <span className="shrink-0 text-[10px] text-faint">{relativeTime(event.createdAt)}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <Link to="/admin/books">
          <Button variant="ghost" size="sm">
            Manage inventory
          </Button>
        </Link>
        <Link to="/admin/users">
          <Button variant="ghost" size="sm">
            Manage patrons
          </Button>
        </Link>
        <Link to="/admin/fines">
          <Button variant="ghost" size="sm">
            Fine dashboard
          </Button>
        </Link>
      </div>
    </>
  )
}
