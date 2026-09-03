import { useEffect, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError } from '../lib/api'
import { useAuth } from '../context/AuthContext'
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, LockIcon, ShieldIcon } from '../components/ui'
import { cx } from '../lib/format'

export default function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, verify2fa } = useAuth()

  // The sign-in page is unauthenticated, so /api/auth/me cannot tell us whether
  // the demo routes are on. /api/health reports it publicly.
  const [labRoutes, setLabRoutes] = useState(false)
  useEffect(() => {
    api
      .health()
      .then(h => setLabRoutes(Boolean(h?.policy?.labRoutes)))
      .catch(() => setLabRoutes(false))
  }, [])

  const [stage, setStage] = useState<'password' | 'otp'>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [challengeId, setChallengeId] = useState('')
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', ''])
  const [secondsLeft, setSecondsLeft] = useState(60)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [demoCode, setDemoCode] = useState<string | null>(null)

  const inputs = useRef<(HTMLInputElement | null)[]>([])
  const from = (location.state as { from?: string } | null)?.from

  // The challenge lives for 60 seconds on the server; mirror that here so the
  // user is never left typing into a window that has already closed.
  useEffect(() => {
    if (stage !== 'otp') return
    setSecondsLeft(60)
    const timer = setInterval(() => {
      setSecondsLeft(current => {
        if (current <= 1) {
          clearInterval(timer)
          return 0
        }
        return current - 1
      })
    }, 1000)
    return () => clearInterval(timer)
  }, [stage, challengeId])

  useEffect(() => {
    if (stage === 'otp') inputs.current[0]?.focus()
  }, [stage])

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const challenge = await login(username.trim(), password)
      setChallengeId(challenge.challengeId)
      setDigits(['', '', '', '', '', ''])
      setDemoCode(null)
      setStage('otp')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.')
    } finally {
      setBusy(false)
    }
  }

  const submitOtp = async (code: string) => {
    setError(null)
    setBusy(true)
    try {
      const user = await verify2fa(challengeId, code)
      navigate(from ?? (user.role === 'admin' ? '/admin' : '/catalog'), { replace: true })
    } catch (err) {
      const apiError = err instanceof ApiError ? err : null
      setError(apiError?.message ?? 'Verification failed.')
      if (apiError?.code === 'CHALLENGE_EXPIRED') {
        setStage('password')
        setPassword('')
      } else {
        setDigits(['', '', '', '', '', ''])
        inputs.current[0]?.focus()
      }
    } finally {
      setBusy(false)
    }
  }

  const setDigit = (index: number, value: string) => {
    const clean = value.replace(/\D/g, '')
    if (!clean && value !== '') return

    if (clean.length > 1) {
      // Paste of a full code.
      const next = clean.slice(0, 6).split('')
      const filled = [...digits]
      for (let i = 0; i < 6; i++) filled[i] = next[i] ?? ''
      setDigits(filled)
      if (filled.every(Boolean)) void submitOtp(filled.join(''))
      else inputs.current[Math.min(next.length, 5)]?.focus()
      return
    }

    const next = [...digits]
    next[index] = clean
    setDigits(next)
    if (clean && index < 5) inputs.current[index + 1]?.focus()
    if (next.every(Boolean)) void submitOtp(next.join(''))
  }

  const onKeyDown = (index: number) => (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) inputs.current[index - 1]?.focus()
    if (e.key === 'ArrowLeft' && index > 0) inputs.current[index - 1]?.focus()
    if (e.key === 'ArrowRight' && index < 5) inputs.current[index + 1]?.focus()
  }

  const fetchDemoCode = async () => {
    try {
      const result = await api.auth.challengeCode(challengeId)
      setDemoCode(result.code)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not read the demo code.')
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-ink px-4 py-10">
      <div className="w-full max-w-md">
        <Link to="/" className="mb-8 flex items-center justify-center gap-2.5">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="#0e1524" stroke="#22304f" />
            <path d="M9 8h11a3 3 0 0 1 3 3v13a3 3 0 0 0-3-3H9z" fill="none" stroke="#34d399" strokeWidth="2" strokeLinejoin="round" />
            <circle cx="16" cy="16" r="2.5" fill="#34d399" />
          </svg>
          <span className="text-sm font-semibold tracking-tight text-slate-50">BookVault</span>
        </Link>

        {stage === 'password' ? (
          <Card className="p-6">
            <div className="mb-1 flex items-center gap-2">
              <Badge tone="neutral">Factor 1 of 2</Badge>
            </div>
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">Sign in</h1>
            <p className="mt-1.5 text-sm text-muted">
              Your password is checked against a salted SHA-256 hash. Nothing is unlocked until the second factor also
              passes.
            </p>

            {error && <ErrorNote className="mt-4">{error}</ErrorNote>}

            <form className="mt-5 space-y-4" onSubmit={submitPassword}>
              <Field label="Username">
                <Input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoFocus required />
              </Field>
              <Field label="Password">
                <Input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </Field>
              <Button type="submit" className="w-full" loading={busy} disabled={!username || !password}>
                Continue
              </Button>
            </form>

            <p className="mt-5 text-center text-xs text-muted">
              No account yet?{' '}
              <Link to="/register" className="text-accent transition-colors hover:text-accent-dim">
                Register as a patron
              </Link>
            </p>
          </Card>
        ) : (
          <Card className="p-6">
            <div className="mb-1 flex items-center justify-between">
              <Badge tone="accent">Factor 2 of 2</Badge>
              <span className={cx('text-xs tabular-nums', secondsLeft <= 10 ? 'text-danger' : 'text-faint')}>
                {secondsLeft > 0 ? `expires in ${secondsLeft}s` : 'expired'}
              </span>
            </div>
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">Enter your six-digit code</h1>
            <p className="mt-1.5 text-sm text-muted">
              Generated from HMAC-SHA256 over the current 30-second time step and your shared secret.
            </p>

            {error && <ErrorNote className="mt-4">{error}</ErrorNote>}

            <div className="mt-5 flex justify-between gap-2">
              {digits.map((digit, index) => (
                <input
                  key={index}
                  ref={el => {
                    inputs.current[index] = el
                  }}
                  value={digit}
                  onChange={e => setDigit(index, e.target.value)}
                  onKeyDown={onKeyDown(index)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  aria-label={`Digit ${index + 1}`}
                  disabled={busy || secondsLeft === 0}
                  className="mono h-14 w-full rounded-lg border border-line bg-surface-2 text-center text-xl text-slate-100 transition-colors focus:border-accent/60 focus:outline-none disabled:opacity-50"
                />
              ))}
            </div>

            <div className="mt-5 flex items-center justify-between gap-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setStage('password')
                  setError(null)
                  setPassword('')
                }}
              >
                Back
              </Button>
              <Button
                size="sm"
                loading={busy}
                disabled={digits.some(d => !d) || secondsLeft === 0}
                onClick={() => submitOtp(digits.join(''))}
              >
                Verify and sign in
              </Button>
            </div>

            {labRoutes && (
              <div className="mt-5 border-t border-line pt-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-xs text-faint">
                    <ShieldIcon size={13} />
                    Demo aid — enabled by ENABLE_LAB_ROUTES
                  </div>
                  <Button size="sm" variant="subtle" onClick={fetchDemoCode} disabled={secondsLeft === 0}>
                    Show current code
                  </Button>
                </div>
                {demoCode && (
                  <InfoNote className="mt-3" tone="accent">
                    Current code: <span className="mono text-base tracking-widest">{demoCode}</span>
                  </InfoNote>
                )}
              </div>
            )}
          </Card>
        )}

        <div className="mt-6 flex items-center justify-center gap-2 text-xs text-faint">
          <LockIcon size={12} />
          Session tokens are 256-bit, stored only as a hash, and bound to your IP and browser.
        </div>
      </div>
    </div>
  )
}
