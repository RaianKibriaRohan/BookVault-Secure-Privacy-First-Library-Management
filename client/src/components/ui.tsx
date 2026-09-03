import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type TextareaHTMLAttributes,
  type SelectHTMLAttributes,
} from 'react'
import { cx } from '../lib/format'
import type { Integrity } from '../lib/api'

// --- Button ----------------------------------------------------------------

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger' | 'subtle' | 'warn'
  size?: 'sm' | 'md'
  loading?: boolean
}

export function Button({ variant = 'primary', size = 'md', loading, className, children, disabled, ...rest }: ButtonProps) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-45 disabled:cursor-not-allowed whitespace-nowrap'
  const sizes = { sm: 'px-3 py-1.5 text-xs', md: 'px-4 py-2 text-sm' }
  const variants = {
    primary: 'bg-accent text-ink hover:bg-accent-dim',
    ghost: 'border border-line text-slate-200 hover:bg-surface-2',
    subtle: 'bg-surface-2 text-slate-200 hover:bg-surface-3',
    danger: 'bg-danger/15 text-danger border border-danger/40 hover:bg-danger/25',
    warn: 'bg-warn/15 text-warn border border-warn/40 hover:bg-warn/25',
  }
  return (
    <button className={cx(base, sizes[size], variants[variant], className)} disabled={disabled || loading} {...rest}>
      {loading && <Spinner size={size === 'sm' ? 12 : 14} />}
      {children}
    </button>
  )
}

// --- Surfaces --------------------------------------------------------------

export function Card({ className, children, ...rest }: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cx('rounded-xl2 border border-line bg-surface', className)} {...rest}>
      {children}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </div>
  )
}

export function Stat({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string
  value: ReactNode
  hint?: string
  tone?: 'default' | 'accent' | 'warn' | 'danger'
}) {
  const tones = {
    default: 'text-slate-50',
    accent: 'text-accent',
    warn: 'text-warn',
    danger: 'text-danger',
  }
  return (
    <Card className="p-4">
      <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className={cx('mt-1.5 text-2xl font-semibold tabular-nums', tones[tone])}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </Card>
  )
}

export function Badge({
  children,
  tone = 'neutral',
  className,
}: {
  children: ReactNode
  tone?: 'neutral' | 'accent' | 'warn' | 'danger' | 'info' | 'violet'
  className?: string
}) {
  const tones = {
    neutral: 'bg-surface-2 text-muted border-line',
    accent: 'bg-accent/12 text-accent border-accent/30',
    warn: 'bg-warn/12 text-warn border-warn/30',
    danger: 'bg-danger/12 text-danger border-danger/30',
    info: 'bg-accent-2/12 text-accent-2 border-accent-2/30',
    violet: 'bg-violet/12 text-violet border-violet/30',
  }
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  )
}

/**
 * The integrity badge is deliberately loud. Every screen that shows decrypted
 * data shows one of these, so the MAC layer is visible rather than implied.
 */
export function IntegrityBadge({ integrity, className }: { integrity: Integrity; className?: string }) {
  if (integrity === 'ok') {
    return (
      <Badge tone="accent" className={className}>
        <CheckIcon /> Verified
      </Badge>
    )
  }
  if (integrity === 'tampered') {
    return (
      <Badge tone="danger" className={className}>
        <AlertIcon /> Tampered — MAC mismatch
      </Badge>
    )
  }
  return (
    <Badge tone="warn" className={className}>
      <AlertIcon /> Undecryptable
    </Badge>
  )
}

export function Spinner({ size = 16, className }: { size?: number; className?: string }) {
  return (
    <svg
      className={cx('animate-spin', className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  )
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl2 border border-dashed border-line px-6 py-14 text-center">
      <div className="mb-2 rounded-lg bg-surface-2 p-2.5 text-faint">
        <BookIcon size={20} />
      </div>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {hint && <p className="mt-1 max-w-sm text-xs text-muted">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

/**
 * Shown when the API reports KEYS_LOCKED — the session is still authenticated,
 * but the server process no longer holds the unwrapped private keys (it was
 * restarted). Nothing can be decrypted until the user signs in again, so the
 * page must say so rather than rendering an empty-looking dashboard.
 */
export function KeysLocked({ onSignOut }: { onSignOut: () => void }) {
  return (
    <Card className="mx-auto max-w-lg p-8 text-center">
      <div className="mx-auto mb-4 w-fit rounded-lg bg-warn/12 p-3 text-warn">
        <LockIcon size={22} />
      </div>
      <h2 className="text-base font-semibold text-slate-100">Your encryption keys are locked</h2>
      <p className="mx-auto mt-2 max-w-sm text-sm leading-relaxed text-muted">
        You are still signed in, but the server no longer holds your unwrapped private keys — they live only in process
        memory and are dropped when the API restarts. Nothing here can be decrypted until you sign in again.
      </p>
      <p className="mx-auto mt-3 max-w-sm text-xs leading-relaxed text-faint">
        This is the intended trade-off: keys are never persisted in usable form, so a database dump — or an
        administrator — cannot read your records.
      </p>
      <div className="mt-5">
        <Button onClick={onSignOut}>Sign in again to unlock</Button>
      </div>
    </Card>
  )
}

export function ErrorNote({ children, className }: { children: ReactNode; className?: string }) {
  if (!children) return null
  return (
    <div className={cx('rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger', className)} role="alert">
      {children}
    </div>
  )
}

export function InfoNote({ children, tone = 'info', className }: { children: ReactNode; tone?: 'info' | 'accent' | 'warn'; className?: string }) {
  const tones = {
    info: 'border-accent-2/30 bg-accent-2/8 text-accent-2',
    accent: 'border-accent/30 bg-accent/8 text-accent',
    warn: 'border-warn/35 bg-warn/8 text-warn',
  }
  return <div className={cx('rounded-lg border px-3 py-2 text-sm', tones[tone], className)}>{children}</div>
}

// --- Form controls ---------------------------------------------------------

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string
  hint?: ReactNode
  error?: string | null
  children: ReactNode
  htmlFor?: string
}) {
  return (
    <label className="block" htmlFor={htmlFor}>
      <span className="mb-1.5 block text-xs font-medium text-muted">{label}</span>
      {children}
      {error ? (
        <span className="mt-1 block text-xs text-danger">{error}</span>
      ) : hint ? (
        <span className="mt-1 block text-xs text-faint">{hint}</span>
      ) : null}
    </label>
  )
}

const controlClass =
  'w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm text-slate-100 placeholder:text-faint transition-colors focus:border-accent/60 focus:outline-none'

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(controlClass, className)} {...rest} />
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(controlClass, 'resize-y', className)} {...rest} />
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cx(controlClass, 'appearance-none pr-8', className)} {...rest}>
      {children}
    </select>
  )
}

// --- Modal -----------------------------------------------------------------

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = 'max-w-lg',
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  width?: string
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-ink/80 p-0 backdrop-blur-sm sm:items-center sm:p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0" onClick={onClose} aria-hidden="true" />
      <div className={cx('relative w-full rounded-t-xl2 border border-line bg-surface shadow-2xl sm:rounded-xl2', width)}>
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          <button onClick={onClose} className="rounded-md p-1 text-faint transition-colors hover:bg-surface-2 hover:text-slate-200" aria-label="Close">
            <CloseIcon />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3.5">{footer}</div>}
      </div>
    </div>
  )
}

// --- Ciphertext viewer -----------------------------------------------------

/**
 * Renders a stored ciphertext. Used all over the app so a patron (and a marker)
 * can see exactly what the database holds next to what it decrypts to.
 */
export function Cipher({ value, label, className }: { value?: string | null; label?: string; className?: string }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  if (!value) return <span className="text-xs text-faint">—</span>

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable - not worth surfacing */
    }
  }

  return (
    <div className={cx('rounded-lg border border-line-soft bg-ink/60 p-2.5', className)}>
      {label && <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-faint">{label}</div>}
      <div className="flex items-start gap-2">
        <code
          className={cx(
            'mono min-w-0 flex-1 text-[11px] leading-relaxed text-accent/70',
            expanded ? 'break-all' : 'block truncate',
          )}
        >
          {value}
        </code>
        <div className="flex shrink-0 gap-1">
          <button
            onClick={() => setExpanded(v => !v)}
            className="rounded px-1.5 py-0.5 text-[10px] text-faint transition-colors hover:bg-surface-2 hover:text-slate-300"
          >
            {expanded ? 'less' : 'more'}
          </button>
          <button
            onClick={copy}
            className="rounded px-1.5 py-0.5 text-[10px] text-faint transition-colors hover:bg-surface-2 hover:text-slate-300"
          >
            {copied ? 'copied' : 'copy'}
          </button>
        </div>
      </div>
      <div className="mt-1 text-[10px] text-faint">{value.length} hex characters</div>
    </div>
  )
}

// --- Toasts ----------------------------------------------------------------

type Toast = { id: number; message: string; tone: 'info' | 'success' | 'error' }
type ToastContextValue = { push: (message: string, tone?: Toast['tone']) => void }

const ToastContext = createContext<ToastContextValue>({ push: () => {} })

export function ToastHost({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const push = useCallback((message: string, tone: Toast['tone'] = 'info') => {
    const id = nextId.current++
    setToasts(current => [...current, { id, message, tone }])
    setTimeout(() => setToasts(current => current.filter(t => t.id !== id)), 4200)
  }, [])

  const value = useMemo(() => ({ push }), [push])

  const tones = {
    info: 'border-line bg-surface-2 text-slate-100',
    success: 'border-accent/40 bg-accent/12 text-accent',
    error: 'border-danger/40 bg-danger/12 text-danger',
  }

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(92vw,22rem)] flex-col gap-2">
        {toasts.map(toast => (
          <div key={toast.id} className={cx('fade-up rounded-lg border px-3.5 py-2.5 text-sm shadow-xl', tones[toast.tone])} role="status">
            {toast.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}

// --- Icons (small inline SVGs, no icon dependency) -------------------------

const iconProps = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

export function CheckIcon({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

export function AlertIcon({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M12 9v4M12 17h.01M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0Z" />
    </svg>
  )
}

export function CloseIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  )
}

export function BookIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z" />
    </svg>
  )
}

export function LockIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  )
}

export function KeyIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="m10.5 12.5 8-8M17 7l3 3M14 10l2 2" />
    </svg>
  )
}

export function ShieldIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
    </svg>
  )
}

export function ChatIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2Z" />
    </svg>
  )
}

export function UserIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}

export function UsersIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  )
}

export function VaultIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <circle cx="12" cy="12" r="4" />
      <path d="M12 8V6M12 18v-2M8 12H6M18 12h-2" />
    </svg>
  )
}

export function CoinIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M15 9.5a3 3 0 0 0-3-1.5c-1.7 0-3 1-3 2s1.3 2 3 2 3 1 3 2-1.3 2-3 2a3 3 0 0 1-3-1.5M12 6v12" />
    </svg>
  )
}

export function ListIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
    </svg>
  )
}

export function StarIcon({ size = 16, filled = false }: { size?: number; filled?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} fill={filled ? 'currentColor' : 'none'} aria-hidden="true">
      <path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8-6.2-3.3-6.2 3.3L7 14.2l-5-4.9 6.9-1Z" />
    </svg>
  )
}

export function SearchIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  )
}

export function ArrowIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  )
}

export function GaugeIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" {...iconProps} aria-hidden="true">
      <path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z" />
      <path d="M13.4 10.6 19 5M3.3 19a9 9 0 1 1 17.4 0Z" />
    </svg>
  )
}
