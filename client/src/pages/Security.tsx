import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type KeyInfo, type RotationResponse } from '../lib/api'
import { useAuth } from '../context/AuthContext'
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  KeyIcon,
  LockIcon,
  Modal,
  PageHeader,
  ShieldIcon,
  Spinner,
  Stat,
  useToast,
} from '../components/ui'
import { fmtDate, relativeTime } from '../lib/format'

const rotationSteps = [
  'A fresh RSA-2048 key pair, secp256k1 key pair and MAC key are generated.',
  'Every checkout, fine and review is verified against its HMAC, decrypted with the old ECC key, re-encrypted with the new one and re-tagged.',
  'Your copy of every chat message is decrypted and re-encrypted under the new RSA key.',
  'Each profile field is re-encrypted and the CBC-MAC is recomputed.',
  'The new key row is written, then the old one is deleted — old keys are destroyed, not archived.',
]

export default function Security() {
  const { user, refresh } = useAuth()
  const toast = useToast()

  const [info, setInfo] = useState<KeyInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [modalOpen, setModalOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [rotating, setRotating] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [result, setResult] = useState<RotationResponse | null>(null)

  const load = useCallback(async () => {
    try {
      setInfo(await api.keys.get())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load your key information.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const rotate = async () => {
    setRotating(true)
    setFormError(null)
    try {
      const response = await api.keys.rotate(password)
      setResult(response)
      setPassword('')
      setModalOpen(false)
      toast.push(`Keys rotated to version ${response.version}.`, 'success')
      await Promise.all([load(), refresh()])
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'Rotation failed.')
    } finally {
      setRotating(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  if (!info) return <ErrorNote>{error ?? 'Key information unavailable.'}</ErrorNote>

  const currentSession = info.sessions.find(s => s.current)
  const totalRekeyed = result
    ? result.report.checkouts.rekeyed + result.report.fines.rekeyed + result.report.reviews.rekeyed + result.report.chat.rekeyed + result.report.profile.rekeyed
    : 0
  const totalTampered = result
    ? result.report.checkouts.tampered + result.report.fines.tampered + result.report.reviews.tampered + result.report.chat.tampered + result.report.profile.tampered
    : 0

  return (
    <>
      <PageHeader
        title="Security"
        subtitle="Your keys, your sessions, and the privacy reset. Nothing on this page reveals private key material — that never leaves the server process."
        actions={<Button onClick={() => setModalOpen(true)}>Rotate my keys</Button>}
      />

      {result && (
        <Card className="mb-6 border-accent/30 bg-accent/5 p-5">
          <div className="flex items-center gap-2">
            <Badge tone="accent">Rotation complete</Badge>
            <span className="text-sm text-muted">
              version {result.report.from} → {result.report.to}
            </span>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {(
              [
                ['Checkouts', result.report.checkouts],
                ['Fines', result.report.fines],
                ['Reviews', result.report.reviews],
                ['Messages', result.report.chat],
                ['Profile fields', result.report.profile],
              ] as const
            ).map(([label, category]) => (
              <div key={label} className="rounded-lg border border-line bg-ink/40 p-3">
                <div className="text-[10px] uppercase tracking-wider text-faint">{label}</div>
                <div className="mt-1 text-lg font-semibold tabular-nums text-accent">{category.rekeyed}</div>
                {category.tampered > 0 && <div className="text-[11px] text-danger">{category.tampered} skipped</div>}
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted">
            {totalRekeyed} records re-encrypted under the new keys.{' '}
            {totalTampered > 0
              ? `${totalTampered} record(s) failed integrity verification and were deliberately left untouched — re-sealing a forged record would destroy the evidence.`
              : 'Every record passed its integrity check.'}
          </p>
        </Card>
      )}

      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat label="Key version" value={`v${info.version}`} hint={`created ${fmtDate(info.createdAt)}`} />
        <Stat label="Rotations" value={Math.max(0, info.version - 1)} hint="old keys destroyed each time" />
        <Stat label="Active sessions" value={info.sessions.filter(s => !s.revoked).length} hint="one at a time is enforced" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-faint">
            <LockIcon size={13} /> RSA-{info.rsa.modulusBits}
          </div>
          <div className="mono text-sm text-accent">{info.rsa.fingerprint}</div>
          <dl className="mt-4 space-y-2 text-xs">
            <div className="flex justify-between border-b border-line-soft pb-1.5">
              <dt className="text-faint">Public exponent</dt>
              <dd className="mono text-slate-300">{info.rsa.publicExponent}</dd>
            </div>
            <div className="flex justify-between border-b border-line-soft pb-1.5">
              <dt className="text-faint">Padding</dt>
              <dd className="text-slate-300">{info.rsa.algorithm}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-faint">Protects</dt>
              <dd className="text-right text-slate-300">{info.rsa.usedFor}</dd>
            </div>
          </dl>
        </Card>

        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-faint">
            <KeyIcon size={13} /> {info.ecc.curve}
          </div>
          <div className="mono text-sm text-accent">{info.ecc.fingerprint}</div>
          <dl className="mt-4 space-y-2 text-xs">
            <div className="flex justify-between border-b border-line-soft pb-1.5">
              <dt className="text-faint">Scheme</dt>
              <dd className="text-right text-slate-300">{info.ecc.algorithm}</dd>
            </div>
            <div className="flex justify-between border-b border-line-soft pb-1.5">
              <dt className="text-faint">Integrity</dt>
              <dd className="text-right text-slate-300">{info.mac.algorithm}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-faint">Protects</dt>
              <dd className="text-right text-slate-300">{info.ecc.usedFor}</dd>
            </div>
          </dl>
        </Card>
      </div>

      <Card className="mt-4 p-5">
        <div className="mb-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-faint">
          <ShieldIcon size={13} /> This session
        </div>
        <dl className="grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <dt className="text-faint">Started</dt>
            <dd className="mt-0.5 text-slate-300">{fmtDate(currentSession?.createdAt, true)}</dd>
          </div>
          <div>
            <dt className="text-faint">Last active</dt>
            <dd className="mt-0.5 text-slate-300">{relativeTime(currentSession?.lastActiveAt)}</dd>
          </div>
          <div>
            <dt className="text-faint">Absolute expiry</dt>
            <dd className="mt-0.5 text-slate-300">{fmtDate(currentSession?.expiresAt, true)}</dd>
          </div>
          <div>
            <dt className="text-faint">Signed in as</dt>
            <dd className="mt-0.5 text-slate-300">
              {user?.username} · {user?.role}
            </dd>
          </div>
        </dl>
        <p className="mt-4 border-t border-line pt-3 text-xs leading-relaxed text-muted">
          The session token is 256 bits of entropy; only its SHA-256 hash is stored. The cookie is HttpOnly, and the
          session is bound to a hash of your IP address and browser — presenting the same cookie from elsewhere revokes
          it and raises an audit event. Sessions end after 30 minutes idle and 12 hours absolute.
        </p>
      </Card>

      {info.history.length > 1 && (
        <Card className="mt-4 p-5">
          <div className="mb-3 text-[11px] font-medium uppercase tracking-wider text-faint">Key history</div>
          <div className="space-y-2 text-xs">
            {info.history.map(entry => (
              <div key={entry.version} className="flex items-center justify-between border-b border-line-soft pb-1.5 last:border-0">
                <span className="text-slate-300">Version {entry.version}</span>
                <span className="text-faint">
                  created {fmtDate(entry.created_at, true)}
                  {entry.retired_at ? ` · retired ${fmtDate(entry.retired_at, true)}` : ' · current'}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="mt-4 p-5">
        <h2 className="text-sm font-semibold text-slate-100">Privacy reset — what rotation does</h2>
        <ol className="mt-3 space-y-2.5">
          {rotationSteps.map((step, index) => (
            <li key={index} className="flex gap-3 text-xs leading-relaxed text-muted">
              <span className="mono mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-line text-[10px] text-faint">
                {index + 1}
              </span>
              {step}
            </li>
          ))}
        </ol>
        <InfoNote className="mt-4" tone="warn">
          Rotation re-encrypts every record you own, so it takes a few seconds and cannot be undone. Your password is
          required, because it derives the key that wraps your private material.
        </InfoNote>
      </Card>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Rotate encryption keys"
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button loading={rotating} disabled={!password} onClick={rotate}>
              Rotate and re-encrypt everything
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {formError && <ErrorNote>{formError}</ErrorNote>}
          <p className="text-sm text-muted">
            A new RSA-2048 and secp256k1 key pair will replace version {info.version}. Every record you own is decrypted
            with the old keys and re-encrypted with the new ones; the old key row is then deleted permanently.
          </p>
          <Field label="Confirm your password" hint="Re-authentication is required for this action.">
            <Input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              autoFocus
              onKeyDown={e => {
                if (e.key === 'Enter' && password) void rotate()
              }}
            />
          </Field>
          {rotating && (
            <InfoNote tone="accent">
              Generating primes and re-encrypting your records — this can take several seconds. Do not close the tab.
            </InfoNote>
          )}
        </div>
      </Modal>
    </>
  )
}
