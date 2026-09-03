import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError, type CheckoutItem, type FineItem, type FineSummary } from '../lib/api'
import { useAuth, useReSignIn } from '../context/AuthContext'
import {
  Badge,
  Button,
  Card,
  Cipher,
  EmptyState,
  ErrorNote,
  InfoNote,
  IntegrityBadge,
  KeysLocked,
  Modal,
  PageHeader,
  Spinner,
  Stat,
  useToast,
} from '../components/ui'
import { cx, fmtBDT, fmtDate } from '../lib/format'

function DueBadge({ item }: { item: CheckoutItem }) {
  if (item.status === 'returned') return <Badge tone="neutral">Returned {fmtDate(item.returnedAt)}</Badge>
  if (item.overdueDays > 0) return <Badge tone="danger">{item.overdueDays} days overdue</Badge>
  if (item.daysLeft <= 3) return <Badge tone="warn">Due in {item.daysLeft} days</Badge>
  return <Badge tone="accent">Due in {item.daysLeft} days</Badge>
}

function FineBreakdown({ rows, amount }: { rows: { tier: string; days: number; rate: number; subtotal: number }[]; amount: number }) {
  return (
    <div className="rounded-lg border border-line-soft bg-ink/50 p-3">
      <table className="w-full text-xs">
        <thead className="text-faint">
          <tr>
            <th className="pb-1.5 text-left font-medium">Tier</th>
            <th className="pb-1.5 text-right font-medium">Days</th>
            <th className="pb-1.5 text-right font-medium">Rate</th>
            <th className="pb-1.5 text-right font-medium">Subtotal</th>
          </tr>
        </thead>
        <tbody className="text-muted">
          {rows.map(row => (
            <tr key={row.tier} className="border-t border-line-soft">
              <td className="py-1.5">{row.tier}</td>
              <td className="py-1.5 text-right tabular-nums">{row.days}</td>
              <td className="py-1.5 text-right tabular-nums">{row.rate} BDT</td>
              <td className="py-1.5 text-right tabular-nums text-slate-300">{row.subtotal} BDT</td>
            </tr>
          ))}
          <tr className="border-t border-line">
            <td className="py-1.5 font-medium text-slate-200" colSpan={3}>
              Total
            </td>
            <td className="py-1.5 text-right font-semibold tabular-nums text-warn">{fmtBDT(amount)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}

export default function Vault() {
  const { labRoutes } = useAuth()
  const reSignIn = useReSignIn()
  const toast = useToast()

  const [checkouts, setCheckouts] = useState<CheckoutItem[]>([])
  const [fines, setFines] = useState<FineItem[]>([])
  const [summary, setSummary] = useState<FineSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [locked, setLocked] = useState(false)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<CheckoutItem | null>(null)
  const [showCipherFor, setShowCipherFor] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [checkoutData, fineData] = await Promise.all([api.checkouts.list(), api.fines.list()])
      setCheckouts(checkoutData.checkouts)
      setFines(fineData.fines)
      setSummary(fineData.summary)
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'KEYS_LOCKED') setLocked(true)
      else setError(err instanceof ApiError ? err.message : 'Could not open your vault.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const doReturn = async (item: CheckoutItem) => {
    setBusyId(item.id)
    setConfirming(null)
    try {
      const result = await api.checkouts.return(item.id)
      toast.push(
        result.fine ? `Returned ${result.daysOverdue} days late — ${fmtBDT(result.fine.amount)} fine issued.` : 'Returned on time.',
        result.fine ? 'error' : 'success',
      )
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Return failed.', 'error')
    } finally {
      setBusyId(null)
    }
  }

  const payFine = async (fine: FineItem) => {
    setBusyId(fine.id)
    try {
      await api.fines.pay(fine.id)
      toast.push(`${fmtBDT(fine.amount)} paid.`, 'success')
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Payment failed.', 'error')
    } finally {
      setBusyId(null)
    }
  }

  const payAll = async () => {
    setBusyId('all')
    try {
      const result = await api.fines.payAll()
      toast.push(`${fmtBDT(result.paid)} cleared across ${result.count} fine(s).`, 'success')
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Payment failed.', 'error')
    } finally {
      setBusyId(null)
    }
  }

  const tamper = async (table: string, id: string) => {
    try {
      await api.lab.tamper(table, id)
      toast.push('One nibble of the stored ciphertext was flipped. Watch the integrity badge.', 'error')
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

  const active = checkouts.filter(c => c.status === 'active')
  const past = checkouts.filter(c => c.status === 'returned')
  const unpaid = fines.filter(f => f.status === 'unpaid')
  const overdue = active.filter(c => c.overdueDays > 0)

  return (
    <>
      <PageHeader
        title="My Vault"
        subtitle="Everything here was fetched as ciphertext, checked against its MAC, and decrypted in memory with your private key. None of it is ever stored decrypted."
        actions={
          <Link to="/catalog">
            <Button variant="ghost">Browse the catalog</Button>
          </Link>
        }
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {summary?.blocked && (
        <div className="mb-5 rounded-xl2 border border-warn/40 bg-warn/8 p-4">
          <div className="text-sm font-medium text-warn">Borrowing is blocked</div>
          <p className="mt-1 text-sm text-muted">
            You have {fmtBDT(summary.outstanding)} in unpaid fines across {summary.unpaidCount}{' '}
            {summary.unpaidCount === 1 ? 'record' : 'records'}. Clear them to borrow again.
          </p>
        </div>
      )}

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Active loans" value={active.length} hint={`${past.length} returned`} />
        <Stat label="Overdue" value={overdue.length} tone={overdue.length ? 'danger' : 'default'} hint={overdue.length ? 'fines accruing' : 'nothing late'} />
        <Stat
          label="Outstanding fines"
          value={fmtBDT(summary?.outstanding ?? 0)}
          tone={summary?.outstanding ? 'warn' : 'default'}
          hint={`${fmtBDT(summary?.paid ?? 0)} paid to date`}
        />
        <Stat
          label="Integrity"
          value={checkouts.filter(c => c.integrity !== 'ok').length === 0 ? 'All verified' : 'Failures found'}
          tone={checkouts.filter(c => c.integrity !== 'ok').length === 0 ? 'accent' : 'danger'}
          hint={`${checkouts.length + fines.length} records checked`}
        />
      </div>

      {/* Currently borrowed */}
      <section className="mb-8">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">Currently borrowed</h2>
        {active.length === 0 ? (
          <EmptyState
            title="Nothing on loan"
            hint="Books you borrow appear here with a live due-date countdown."
            action={
              <Link to="/catalog">
                <Button size="sm">Find something to read</Button>
              </Link>
            }
          />
        ) : (
          <div className="space-y-3">
            {active.map(item => (
              <Card
                key={item.id}
                className={cx(
                  'p-4',
                  item.integrity !== 'ok' && 'border-danger/40 bg-danger/5',
                  item.overdueDays > 0 && item.integrity === 'ok' && 'border-warn/35',
                )}
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-slate-100">
                        {item.book?.title ?? <span className="text-danger">Record could not be opened</span>}
                      </h3>
                      <IntegrityBadge integrity={item.integrity} />
                    </div>
                    {item.book && <p className="mt-0.5 text-xs text-muted">{item.book.author}</p>}
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-faint">
                      <DueBadge item={item} />
                      <span>Borrowed {fmtDate(item.checkoutDate)}</span>
                      <span>·</span>
                      <span>Due {fmtDate(item.dueDate)}</span>
                      <span>·</span>
                      <span>key v{item.keyVersion}</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-2">
                    <Button
                      size="sm"
                      variant={item.overdueDays > 0 ? 'warn' : 'primary'}
                      loading={busyId === item.id}
                      disabled={item.integrity !== 'ok'}
                      onClick={() => setConfirming(item)}
                    >
                      Return
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setShowCipherFor(showCipherFor === item.id ? null : item.id)}>
                      {showCipherFor === item.id ? 'Hide stored row' : 'Stored row'}
                    </Button>
                    {labRoutes && item.integrity === 'ok' && (
                      <Button size="sm" variant="danger" onClick={() => tamper('checkouts', item.id)}>
                        Simulate tampering
                      </Button>
                    )}
                  </div>
                </div>

                {item.integrity === 'tampered' && (
                  <ErrorNote className="mt-3">
                    This record failed its HMAC check. It has been altered in the database since it was written, so
                    decryption was refused and the return action is disabled. The event is in the audit log.
                  </ErrorNote>
                )}

                {item.projectedFine && item.projectedFine.amount > 0 && (
                  <div className="mt-3">
                    <div className="mb-1.5 text-xs text-warn">
                      Fine accruing if returned today: {fmtBDT(item.projectedFine.amount)}
                      {item.projectedFine.replacementNotice && ' · replacement notice would be issued'}
                    </div>
                    <FineBreakdown rows={item.projectedFine.breakdown} amount={item.projectedFine.amount} />
                  </div>
                )}

                {showCipherFor === item.id && (
                  <div className="mt-3 space-y-2">
                    <Cipher label="ciphertext as stored" value={item.raw.ciphertext} />
                    <Cipher label="hmac_tag" value={item.raw.hmacTag} />
                  </div>
                )}
              </Card>
            ))}
          </div>
        )}
      </section>

      {/* Fines */}
      <section className="mb-8">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Fines</h2>
          {unpaid.length > 1 && (
            <Button size="sm" variant="warn" loading={busyId === 'all'} onClick={payAll}>
              Pay all ({fmtBDT(summary?.outstanding ?? 0)})
            </Button>
          )}
        </div>

        {fines.length === 0 ? (
          <EmptyState title="No fines" hint="Return your books on time and this stays empty." />
        ) : (
          <div className="space-y-3">
            {fines.map(fine => (
              <Card key={fine.id} className={cx('p-4', fine.status === 'unpaid' ? 'border-warn/35' : '')}>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-slate-100">
                        {fine.detail?.title ?? <span className="text-danger">Fine record could not be opened</span>}
                      </h3>
                      <IntegrityBadge integrity={fine.integrity} />
                      {fine.status === 'paid' ? <Badge tone="accent">Paid</Badge> : <Badge tone="warn">Unpaid</Badge>}
                      {fine.replacementNotice && <Badge tone="danger">Replacement notice</Badge>}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-faint">
                      <span className="text-warn">{fmtBDT(fine.amount)}</span>
                      <span>·</span>
                      <span>{fine.daysOverdue} days overdue</span>
                      {fine.detail && (
                        <>
                          <span>·</span>
                          <span>due {fmtDate(fine.detail.dueDate)}</span>
                          <span>·</span>
                          <span>returned {fmtDate(fine.detail.returnedAt)}</span>
                        </>
                      )}
                    </div>
                  </div>
                  {fine.status === 'unpaid' && (
                    <Button size="sm" variant="warn" loading={busyId === fine.id} onClick={() => payFine(fine)}>
                      Pay {fmtBDT(fine.amount)}
                    </Button>
                  )}
                </div>

                {fine.detail?.breakdown?.length ? (
                  <div className="mt-3">
                    <FineBreakdown rows={fine.detail.breakdown} amount={fine.amount} />
                  </div>
                ) : null}

                {fine.replacementNotice && (
                  <InfoNote tone="warn" className="mt-3">
                    Returned 15 or more days late — a book replacement notice has been issued alongside this fine.
                  </InfoNote>
                )}
              </Card>
            ))}
          </div>
        )}
      </section>

      {/* History */}
      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-200">Past checkouts</h2>
        {past.length === 0 ? (
          <EmptyState title="No history yet" hint="Returned books appear here." />
        ) : (
          <Card className="overflow-x-auto">
            <table className="w-full min-w-[36rem] text-left text-sm">
              <thead className="border-b border-line text-xs text-faint">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Book</th>
                  <th className="px-4 py-2.5 font-medium">Borrowed</th>
                  <th className="px-4 py-2.5 font-medium">Due</th>
                  <th className="px-4 py-2.5 font-medium">Returned</th>
                  <th className="px-4 py-2.5 font-medium">Integrity</th>
                </tr>
              </thead>
              <tbody>
                {past.map(item => (
                  <tr key={item.id} className="border-b border-line-soft last:border-0">
                    <td className="px-4 py-2.5">
                      <div className="text-slate-200">{item.book?.title ?? '—'}</div>
                      {item.book && <div className="text-xs text-faint">{item.book.author}</div>}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted">{fmtDate(item.checkoutDate)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted">{fmtDate(item.dueDate)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted">
                      {fmtDate(item.returnedAt)}
                      {item.overdueDays > 0 && <span className="ml-1.5 text-danger">+{item.overdueDays}d</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <IntegrityBadge integrity={item.integrity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </section>

      <Modal
        open={Boolean(confirming)}
        onClose={() => setConfirming(null)}
        title="Return this book"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(null)}>
              Cancel
            </Button>
            <Button variant={confirming && confirming.overdueDays > 0 ? 'warn' : 'primary'} onClick={() => confirming && doReturn(confirming)}>
              {confirming && confirming.overdueDays > 0 ? `Return and accept ${fmtBDT(confirming.projectedFine?.amount ?? 0)}` : 'Confirm return'}
            </Button>
          </>
        }
      >
        {confirming && (
          <div className="space-y-3 text-sm">
            <p className="text-muted">
              Returning <span className="text-slate-100">{confirming.book?.title}</span> re-seals the record with a new
              status and a fresh HMAC tag, and puts the copy back on the shelf.
            </p>
            {confirming.overdueDays > 0 && confirming.projectedFine ? (
              <>
                <InfoNote tone="warn">
                  This book is {confirming.overdueDays} days overdue. A fine of {fmtBDT(confirming.projectedFine.amount)}{' '}
                  will be created — itself encrypted and MAC-tagged.
                </InfoNote>
                <FineBreakdown rows={confirming.projectedFine.breakdown} amount={confirming.projectedFine.amount} />
              </>
            ) : (
              <InfoNote tone="accent">On time — no fine will be charged.</InfoNote>
            )}
          </div>
        )}
      </Modal>
    </>
  )
}
