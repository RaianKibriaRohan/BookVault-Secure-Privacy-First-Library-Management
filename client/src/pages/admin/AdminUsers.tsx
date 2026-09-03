import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type AdminUser } from '../../lib/api'
import { Badge, Button, Card, ErrorNote, InfoNote, Modal, PageHeader, Spinner, useToast } from '../../components/ui'
import { fmtBDT, fmtDate, relativeTime } from '../../lib/format'

export default function AdminUsers() {
  const toast = useToast()
  const [users, setUsers] = useState<AdminUser[]>([])
  const [note, setNote] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [target, setTarget] = useState<AdminUser | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.admin.users()
      setUsers(data.users)
      setNote(data.note)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load the patron list.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const setStatus = async (user: AdminUser) => {
    setBusy(true)
    const next = user.status === 'active' ? 'suspended' : 'active'
    try {
      await api.admin.setUserStatus(user.id, next)
      toast.push(`${user.username} is now ${next}.`, next === 'suspended' ? 'error' : 'success')
      setTarget(null)
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not change the account status.', 'error')
    } finally {
      setBusy(false)
    }
  }

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
        title="Patrons"
        subtitle="Account administration: who is registered, when they last signed in, and whether their account is active."
      />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      <InfoNote className="mb-5">{note || 'Encrypted profile fields are deliberately absent from this endpoint.'}</InfoNote>

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[52rem] text-left text-sm">
          <thead className="border-b border-line text-xs text-faint">
            <tr>
              <th className="px-4 py-2.5 font-medium">Account</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Registered</th>
              <th className="px-4 py-2.5 font-medium">Last sign-in</th>
              <th className="px-4 py-2.5 font-medium">Records</th>
              <th className="px-4 py-2.5 font-medium">Fines</th>
              <th className="px-4 py-2.5 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className="border-b border-line-soft last:border-0">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <span className="mono flex h-8 w-8 items-center justify-center rounded-full bg-surface-2 text-xs text-muted">
                      {user.username.slice(0, 2).toUpperCase()}
                    </span>
                    <div>
                      <div className="text-slate-200">{user.username}</div>
                      <div className="text-[11px] text-faint">key v{user.keyVersion}</div>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1.5">
                    <Badge tone={user.role === 'admin' ? 'violet' : 'info'}>{user.role}</Badge>
                    <Badge tone={user.status === 'active' ? 'accent' : 'danger'}>{user.status}</Badge>
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-muted">{fmtDate(user.createdAt)}</td>
                <td className="px-4 py-3 text-xs text-muted">
                  {user.lastLoginAt ? relativeTime(user.lastLoginAt) : 'never'}
                  {user.failedLogins > 0 && <div className="text-[11px] text-warn">{user.failedLogins} failed attempts</div>}
                </td>
                <td className="px-4 py-3 text-xs text-muted">
                  {user.checkouts} checkouts
                  {user.activeCheckouts > 0 && <div className="text-[11px] text-faint">{user.activeCheckouts} active</div>}
                </td>
                <td className="px-4 py-3 text-xs">
                  {user.outstandingFines > 0 ? (
                    <span className="text-warn">{fmtBDT(user.outstandingFines)}</span>
                  ) : (
                    <span className="text-faint">clear</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex justify-end">
                    {user.role === 'admin' ? (
                      <span className="text-[11px] text-faint">staff account</span>
                    ) : (
                      <Button size="sm" variant={user.status === 'active' ? 'danger' : 'ghost'} onClick={() => setTarget(user)}>
                        {user.status === 'active' ? 'Suspend' : 'Reactivate'}
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Modal
        open={Boolean(target)}
        onClose={() => setTarget(null)}
        title={target?.status === 'active' ? 'Suspend this account' : 'Reactivate this account'}
        footer={
          <>
            <Button variant="ghost" onClick={() => setTarget(null)}>
              Cancel
            </Button>
            <Button variant={target?.status === 'active' ? 'danger' : 'primary'} loading={busy} onClick={() => target && setStatus(target)}>
              {target?.status === 'active' ? 'Suspend immediately' : 'Reactivate'}
            </Button>
          </>
        }
      >
        {target && (
          <div className="space-y-3 text-sm text-muted">
            {target.status === 'active' ? (
              <>
                <p>
                  Suspending <span className="text-slate-100">{target.username}</span> takes effect immediately: every
                  live session is revoked and their unwrapped keys are dropped from server memory. They will not be able
                  to sign in until the account is reactivated.
                </p>
                {target.activeCheckouts > 0 && (
                  <InfoNote tone="warn">
                    This patron has {target.activeCheckouts} book(s) on loan. Suspension does not return them.
                  </InfoNote>
                )}
              </>
            ) : (
              <p>
                <span className="text-slate-100">{target.username}</span> will be able to sign in again. Their encrypted
                records were never touched by the suspension.
              </p>
            )}
          </div>
        )}
      </Modal>
    </>
  )
}
