import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, ApiError, type RegisterResponse } from '../lib/api'
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, KeyIcon, LockIcon, Spinner } from '../components/ui'
import { cx } from '../lib/format'

type Step = 'account' | 'contact' | 'generating' | 'done'

const strengthOf = (password: string) => {
  let score = 0
  if (password.length >= 8) score++
  if (password.length >= 12) score++
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++
  if (/\d/.test(password)) score++
  if (/[^A-Za-z0-9]/.test(password)) score++
  return Math.min(score, 5)
}

const strengthLabels = ['Too short', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent']

export default function Register() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('account')
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RegisterResponse | null>(null)
  const [copied, setCopied] = useState(false)

  const [form, setForm] = useState({
    username: '',
    password: '',
    confirm: '',
    fullName: '',
    email: '',
    phone: '',
    libraryCard: '',
    address: '',
  })

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(current => ({ ...current, [key]: e.target.value }))

  const strength = useMemo(() => strengthOf(form.password), [form.password])

  const accountErrors = useMemo(() => {
    const errors: Record<string, string> = {}
    if (form.username && !/^[a-zA-Z0-9_.-]{3,32}$/.test(form.username)) {
      errors.username = '3–32 characters: letters, digits, dot, underscore or hyphen.'
    }
    if (form.password && form.password.length < 8) errors.password = 'At least 8 characters.'
    if (form.confirm && form.confirm !== form.password) errors.confirm = 'The two passwords do not match.'
    return errors
  }, [form])

  const accountReady =
    form.username.length >= 3 &&
    form.password.length >= 8 &&
    form.confirm === form.password &&
    Object.keys(accountErrors).length === 0

  const contactReady =
    form.fullName.trim().length > 0 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(form.email) &&
    form.phone.trim().length >= 6 &&
    form.libraryCard.trim().length > 0

  const submit = async () => {
    setError(null)
    setStep('generating')
    try {
      const response = await api.auth.register({
        username: form.username.trim(),
        password: form.password,
        email: form.email.trim(),
        phone: form.phone.trim(),
        libraryCard: form.libraryCard.trim(),
        fullName: form.fullName.trim(),
        address: form.address.trim(),
      })
      setResult(response)
      setStep('done')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Registration failed.')
      setStep('contact')
    }
  }

  const copySecret = async () => {
    if (!result) return
    try {
      await navigator.clipboard.writeText(result.totpSecret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="min-h-screen bg-ink px-4 py-10">
      <div className="mx-auto w-full max-w-xl">
        <Link to="/" className="mb-8 flex items-center gap-2.5">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="#0e1524" stroke="#22304f" />
            <path d="M9 8h11a3 3 0 0 1 3 3v13a3 3 0 0 0-3-3H9z" fill="none" stroke="#34d399" strokeWidth="2" strokeLinejoin="round" />
            <circle cx="16" cy="16" r="2.5" fill="#34d399" />
          </svg>
          <span className="text-sm font-semibold tracking-tight text-slate-50">BookVault</span>
        </Link>

        {/* Progress */}
        {step !== 'done' && (
          <div className="mb-6 flex items-center gap-2 text-xs">
            {(['account', 'contact', 'generating'] as const).map((name, index) => {
              const order = ['account', 'contact', 'generating']
              const currentIndex = order.indexOf(step)
              const state = index < currentIndex ? 'done' : index === currentIndex ? 'current' : 'todo'
              return (
                <div key={name} className="flex flex-1 items-center gap-2">
                  <div
                    className={cx(
                      'flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-medium',
                      state === 'done' && 'border-accent/40 bg-accent/15 text-accent',
                      state === 'current' && 'border-accent bg-accent text-ink',
                      state === 'todo' && 'border-line text-faint',
                    )}
                  >
                    {index + 1}
                  </div>
                  <span className={cx('capitalize', state === 'todo' ? 'text-faint' : 'text-muted')}>
                    {name === 'generating' ? 'keys' : name}
                  </span>
                  {index < 2 && <div className="h-px flex-1 bg-line" />}
                </div>
              )
            })}
          </div>
        )}

        {step === 'account' && (
          <Card className="p-6">
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">Create your patron account</h1>
            <p className="mt-1.5 text-sm text-muted">
              Your password is never stored. Only a salted SHA-256 hash of it reaches the database — and it also derives
              the key that protects your private keys.
            </p>

            <div className="mt-5 space-y-4">
              <Field label="Username" error={accountErrors.username} hint="Letters, digits, dot, underscore or hyphen.">
                <Input value={form.username} onChange={set('username')} autoComplete="username" placeholder="e.g. faiza.s" autoFocus />
              </Field>

              <Field label="Password" error={accountErrors.password}>
                <Input type="password" value={form.password} onChange={set('password')} autoComplete="new-password" />
              </Field>

              {form.password && (
                <div>
                  <div className="flex gap-1">
                    {[0, 1, 2, 3, 4].map(i => (
                      <div
                        key={i}
                        className={cx(
                          'h-1 flex-1 rounded-full transition-colors',
                          i < strength ? (strength <= 2 ? 'bg-danger' : strength <= 3 ? 'bg-warn' : 'bg-accent') : 'bg-surface-3',
                        )}
                      />
                    ))}
                  </div>
                  <div className="mt-1.5 text-xs text-muted">{strengthLabels[strength]}</div>
                </div>
              )}

              <Field label="Confirm password" error={accountErrors.confirm}>
                <Input type="password" value={form.confirm} onChange={set('confirm')} autoComplete="new-password" />
              </Field>
            </div>

            <div className="mt-6 flex items-center justify-between">
              <Link to="/login" className="text-xs text-muted transition-colors hover:text-slate-200">
                Already registered? Sign in
              </Link>
              <Button disabled={!accountReady} onClick={() => setStep('contact')}>
                Continue
              </Button>
            </div>
          </Card>
        )}

        {step === 'contact' && (
          <Card className="p-6">
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">Contact details</h1>
            <p className="mt-1.5 text-sm text-muted">
              Each of these fields is encrypted individually with your own RSA-2048 public key before it is stored, then
              covered by a single CBC-MAC tag. Nobody else — the librarian included — can read them.
            </p>

            {error && <ErrorNote className="mt-4">{error}</ErrorNote>}

            <div className="mt-5 space-y-4">
              <Field label="Full name">
                <Input value={form.fullName} onChange={set('fullName')} placeholder="Faiza Surma" autoFocus />
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Email">
                  <Input type="email" value={form.email} onChange={set('email')} placeholder="you@university.edu" />
                </Field>
                <Field label="Phone">
                  <Input value={form.phone} onChange={set('phone')} placeholder="+8801700000000" />
                </Field>
              </div>
              <Field label="Library card number">
                <Input value={form.libraryCard} onChange={set('libraryCard')} placeholder="LIB-000123" />
              </Field>
              <Field label="Address" hint="Optional.">
                <Input value={form.address} onChange={set('address')} placeholder="12 Vault Road, Dhaka" />
              </Field>
            </div>

            <InfoNote className="mt-5" tone="warn">
              Creating your account generates an RSA-2048 key pair and a secp256k1 key pair on the server. Prime
              generation takes a few seconds — please do not close the tab.
            </InfoNote>

            <div className="mt-6 flex items-center justify-between">
              <Button variant="ghost" onClick={() => setStep('account')}>
                Back
              </Button>
              <Button disabled={!contactReady} onClick={submit}>
                Create account and generate keys
              </Button>
            </div>
          </Card>
        )}

        {step === 'generating' && (
          <Card className="p-10 text-center">
            <div className="pulse-ring mx-auto w-fit rounded-full bg-accent/12 p-4 text-accent">
              <KeyIcon size={26} />
            </div>
            <h1 className="mt-5 text-lg font-semibold text-slate-50">Generating your keys</h1>
            <p className="mx-auto mt-2 max-w-sm text-sm text-muted">
              Searching for two 1024-bit primes with Miller–Rabin, deriving the RSA modulus, generating a secp256k1
              scalar and wrapping everything under your password.
            </p>
            <div className="mt-6 flex items-center justify-center gap-2 text-sm text-accent">
              <Spinner size={16} /> This usually takes 2–6 seconds
            </div>
          </Card>
        )}

        {step === 'done' && result && (
          <Card className="p-6">
            <Badge tone="accent" className="mb-3">
              Account created
            </Badge>
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">Save your two-factor secret</h1>
            <p className="mt-1.5 text-sm text-muted">
              This secret is shown <span className="text-danger">exactly once</span>. It is stored only in wrapped form,
              so it cannot be recovered or re-displayed later. Add it to an authenticator app now.
            </p>

            <div className="mt-5 rounded-lg border border-accent/30 bg-accent/8 p-4">
              <div className="text-[10px] font-medium uppercase tracking-wider text-accent">TOTP secret (base32)</div>
              <div className="mono mt-2 break-all text-sm leading-relaxed text-accent">{result.totpSecret}</div>
              <div className="mt-3 flex gap-2">
                <Button size="sm" variant="subtle" onClick={copySecret}>
                  {copied ? 'Copied' : 'Copy secret'}
                </Button>
              </div>
            </div>

            <div className="mt-4 rounded-lg border border-line bg-ink/50 p-3">
              <div className="text-[10px] font-medium uppercase tracking-wider text-faint">otpauth URI</div>
              <code className="mono mt-1.5 block break-all text-[11px] leading-relaxed text-muted">{result.totpUri}</code>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-line bg-ink/50 p-3">
                <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-faint">
                  <LockIcon size={11} /> RSA-{result.fingerprints.rsaBits}
                </div>
                <div className="mono mt-1.5 text-xs text-slate-300">{result.fingerprints.rsa}</div>
              </div>
              <div className="rounded-lg border border-line bg-ink/50 p-3">
                <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-faint">
                  <KeyIcon size={11} /> {result.fingerprints.curve}
                </div>
                <div className="mono mt-1.5 text-xs text-slate-300">{result.fingerprints.ecc}</div>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <Button onClick={() => navigate('/login')}>I have saved it — continue to sign in</Button>
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
