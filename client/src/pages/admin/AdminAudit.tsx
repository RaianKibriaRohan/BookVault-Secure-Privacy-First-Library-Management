import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type AuditEntry } from '../../lib/api'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Input,
  PageHeader,
  SearchIcon,
  Select,
  Spinner,
} from '../../components/ui'
import { cx, fmtDate, humanEvent, relativeTime } from '../../lib/format'

const LEGEND: [string, string][] = [
  ['register', 'A new account was created and its key pairs generated.'],
  ['login', 'Password factor attempted — success or failure.'],
  ['2fa', 'Second factor attempted.'],
  ['session_hijack_suspected', 'A session token arrived from a different IP or browser; the session was revoked.'],
  ['rbac_denied', 'A caller was refused an endpoint their role does not permit.'],
  ['integrity_failure', 'A stored record failed its MAC check when it was read.'],
  ['key_rotation', 'A patron regenerated their keys and re-encrypted their records.'],
  ['fine_issued', 'A book was returned late and a fine record was created.'],
  ['lab_tamper', 'The demo endpoint deliberately corrupted a ciphertext.'],
]

export default function AdminAudit() {
  const [events, setEvents] = useState<AuditEntry[]>([])
  const [eventTypes, setEventTypes] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [event, setEvent] = useState('')
  const [outcome, setOutcome] = useState('')
  const [username, setUsername] = useState('')
  const [limit, setLimit] = useState('100')
  const [showLegend, setShowLegend] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.admin.audit({
        event: event || undefined,
        outcome: outcome || undefined,
        username: username.trim() || undefined,
        limit,
      })
      setEvents(data.events)
      setEventTypes(data.eventTypes)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load the audit log.')
    } finally {
      setLoading(false)
    }
  }, [event, outcome, username, limit])

  useEffect(() => {
    const timer = setTimeout(() => void load(), 200)
    return () => clearTimeout(timer)
  }, [load])

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Security-relevant events with metadata only — who, what, when and from where. No encrypted content and no decrypted content is ever written here."
        actions={
          <Button variant="ghost" onClick={() => setShowLegend(v => !v)}>
            {showLegend ? 'Hide legend' : 'Event legend'}
          </Button>
        }
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {showLegend && (
        <Card className="mb-5 p-4">
          <div className="grid gap-2 sm:grid-cols-2">
            {LEGEND.map(([type, description]) => (
              <div key={type} className="flex gap-2 text-xs">
                <span className="mono shrink-0 text-accent/70">{type}</span>
                <span className="text-muted">{description}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Select value={event} onChange={e => setEvent(e.target.value)} aria-label="Filter by event type">
          <option value="">All event types</option>
          {eventTypes.map(type => (
            <option key={type} value={type}>
              {humanEvent(type)}
            </option>
          ))}
        </Select>
        <Select value={outcome} onChange={e => setOutcome(e.target.value)} aria-label="Filter by outcome">
          <option value="">All outcomes</option>
          <option value="success">Success</option>
          <option value="warning">Warning</option>
          <option value="failure">Failure</option>
        </Select>
        <div className="relative">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint">
            <SearchIcon size={15} />
          </span>
          <Input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" className="pl-9" />
        </div>
        <Select value={limit} onChange={e => setLimit(e.target.value)} aria-label="Number of rows">
          <option value="50">Last 50</option>
          <option value="100">Last 100</option>
          <option value="250">Last 250</option>
          <option value="500">Last 500</option>
        </Select>
      </div>

      {loading ? (
        <div className="flex justify-center py-20 text-muted">
          <Spinner size={22} />
        </div>
      ) : events.length === 0 ? (
        <EmptyState title="No events match those filters" hint="Try widening the event type or outcome." />
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[46rem] text-left text-sm">
            <thead className="border-b border-line text-xs text-faint">
              <tr>
                <th className="px-4 py-2.5 font-medium">Event</th>
                <th className="px-4 py-2.5 font-medium">Account</th>
                <th className="px-4 py-2.5 font-medium">Detail</th>
                <th className="px-4 py-2.5 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {events.map(entry => (
                <tr key={entry.id} className="border-b border-line-soft last:border-0">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={cx(
                          'h-1.5 w-1.5 shrink-0 rounded-full',
                          entry.outcome === 'success' ? 'bg-accent' : entry.outcome === 'warning' ? 'bg-warn' : 'bg-danger',
                        )}
                      />
                      <span className="text-slate-200">{humanEvent(entry.eventType)}</span>
                      {entry.outcome !== 'success' && (
                        <Badge tone={entry.outcome === 'warning' ? 'warn' : 'danger'}>{entry.outcome}</Badge>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted">{entry.username ?? '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-muted">{entry.detail || '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-faint" title={fmtDate(entry.createdAt, true)}>
                    <div>{relativeTime(entry.createdAt)}</div>
                    <div className="text-[10px]">{fmtDate(entry.createdAt, true)}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <div className="mt-4 text-xs text-faint">
        Showing {events.length} event{events.length === 1 ? '' : 's'}, newest first.
      </div>
    </>
  )
}
