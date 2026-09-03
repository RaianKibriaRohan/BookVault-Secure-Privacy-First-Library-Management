import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { cx } from '../lib/format'
import {
  Badge,
  BookIcon,
  ChatIcon,
  CoinIcon,
  GaugeIcon,
  KeyIcon,
  ListIcon,
  StarIcon,
  UserIcon,
  UsersIcon,
  VaultIcon,
} from './ui'

const patronNav = [
  { to: '/catalog', label: 'Catalog', icon: BookIcon },
  { to: '/vault', label: 'My Vault', icon: VaultIcon },
  { to: '/reviews', label: 'Reviews', icon: StarIcon },
  { to: '/chat', label: 'Chat', icon: ChatIcon },
  { to: '/profile', label: 'Profile', icon: UserIcon },
  { to: '/security', label: 'Security', icon: KeyIcon },
]

const adminNav = [
  { to: '/admin', label: 'Overview', icon: GaugeIcon, end: true },
  { to: '/admin/books', label: 'Books', icon: BookIcon },
  { to: '/admin/users', label: 'Patrons', icon: UsersIcon },
  { to: '/admin/fines', label: 'Fines', icon: CoinIcon },
  { to: '/admin/chat', label: 'Chat', icon: ChatIcon },
  { to: '/admin/audit', label: 'Audit Log', icon: ListIcon },
]

function BookVaultMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#0e1524" stroke="#22304f" />
      <path
        d="M9 8h11a3 3 0 0 1 3 3v13a3 3 0 0 0-3-3H9z"
        fill="none"
        stroke="#34d399"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="2.5" fill="#34d399" />
    </svg>
  )
}

/** Counts down to the idle timeout so the session policy is visible, not silent. */
function IdleCountdown() {
  const { session } = useAuth()
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(timer)
  }, [])

  if (!session?.lastActiveAt) return null
  const deadline = new Date(session.lastActiveAt).getTime() + session.idleTimeoutMinutes * 60_000
  const minutes = Math.max(0, Math.round((deadline - now) / 60_000))

  return (
    <span className="hidden text-xs text-faint lg:inline" title={`Signed out automatically after ${session.idleTimeoutMinutes} minutes of inactivity`}>
      idle timeout in {minutes}m
    </span>
  )
}

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    setMenuOpen(false)
  }, [location.pathname])

  if (!user) return null
  const items = user.role === 'admin' ? adminNav : patronNav

  const signOut = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  const navLinks = (
    <nav className="flex flex-col gap-0.5">
      {items.map(item => {
        const Icon = item.icon
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={'end' in item ? (item.end as boolean) : undefined}
            className={({ isActive }) =>
              cx(
                'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors',
                isActive ? 'bg-accent/12 text-accent' : 'text-muted hover:bg-surface-2 hover:text-slate-200',
              )
            }
          >
            <Icon size={16} />
            {item.label}
          </NavLink>
        )
      })}
    </nav>
  )

  return (
    <div className="min-h-screen bg-ink">
      {/* Sidebar - desktop */}
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-line bg-surface/60 px-3 py-4 md:flex">
        <div className="mb-6 flex items-center gap-2.5 px-2">
          <BookVaultMark />
          <div>
            <div className="text-sm font-semibold tracking-tight text-slate-50">BookVault</div>
            <div className="text-[10px] uppercase tracking-wider text-faint">
              {user.role === 'admin' ? 'Librarian console' : 'Patron'}
            </div>
          </div>
        </div>
        {navLinks}
        <div className="mt-auto rounded-lg border border-line-soft bg-ink/50 p-3">
          <div className="text-[10px] uppercase tracking-wider text-faint">Encryption</div>
          <div className="mt-1 text-xs text-muted">RSA-2048 · secp256k1</div>
          <div className="mt-1 text-xs text-muted">key version {user.keyVersion}</div>
        </div>
      </aside>

      <div className="md:pl-60">
        {/* Topbar */}
        <header className="sticky top-0 z-30 border-b border-line bg-ink/85 backdrop-blur">
          <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
            <button
              className="rounded-md p-1.5 text-muted transition-colors hover:bg-surface-2 md:hidden"
              onClick={() => setMenuOpen(v => !v)}
              aria-label="Toggle navigation"
              aria-expanded={menuOpen}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <div className="flex items-center gap-2 md:hidden">
              <BookVaultMark size={22} />
              <span className="text-sm font-semibold text-slate-50">BookVault</span>
            </div>

            <div className="ml-auto flex items-center gap-3">
              <IdleCountdown />
              <div className="hidden text-right sm:block">
                <div className="text-xs font-medium text-slate-200">{user.username}</div>
                <div className="text-[10px] text-faint">key v{user.keyVersion}</div>
              </div>
              <Badge tone={user.role === 'admin' ? 'violet' : 'info'}>{user.role === 'admin' ? 'Head Librarian' : 'Patron'}</Badge>
              <button
                onClick={signOut}
                className="rounded-lg border border-line px-3 py-1.5 text-xs text-muted transition-colors hover:bg-surface-2 hover:text-slate-200"
              >
                Sign out
              </button>
            </div>
          </div>

          {menuOpen && (
            <div className="border-t border-line bg-surface px-3 py-3 md:hidden">{navLinks}</div>
          )}
        </header>

        <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
