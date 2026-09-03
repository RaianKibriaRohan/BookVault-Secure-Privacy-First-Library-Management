import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, type MeResponse, type Role, type SessionInfo, type User } from '../lib/api'
import { Spinner, Card, ShieldIcon } from '../components/ui'

interface AuthValue {
  user: User | null
  session: SessionInfo | null
  keysUnlocked: boolean
  labRoutes: boolean
  loading: boolean
  refresh: () => Promise<void>
  login: (username: string, password: string) => Promise<{ challengeId: string; expiresIn: number }>
  verify2fa: (challengeId: string, code: string) => Promise<User>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthValue>(null as unknown as AuthValue)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ me: MeResponse | null; loading: boolean }>({ me: null, loading: true })

  const refresh = useCallback(async () => {
    try {
      const me = await api.auth.me()
      setState({ me, loading: false })
    } catch {
      // A 401 here is the normal signed-out case, not an error worth surfacing.
      setState({ me: null, loading: false })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const login = useCallback(async (username: string, password: string) => {
    const challenge = await api.auth.login(username, password)
    return { challengeId: challenge.challengeId, expiresIn: challenge.expiresIn }
  }, [])

  const verify2fa = useCallback(
    async (challengeId: string, code: string) => {
      const result = await api.auth.verify2fa(challengeId, code)
      await refresh()
      return result.user
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    try {
      await api.auth.logout()
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
    }
    setState({ me: null, loading: false })
  }, [])

  const value = useMemo<AuthValue>(
    () => ({
      user: state.me?.user ?? null,
      session: state.me?.session ?? null,
      keysUnlocked: state.me?.keysUnlocked ?? false,
      labRoutes: state.me?.labRoutes ?? false,
      loading: state.loading,
      refresh,
      login,
      verify2fa,
      logout,
    }),
    [state, refresh, login, verify2fa, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}

/**
 * Ends the session and returns to sign-in. Used by the KEYS_LOCKED recovery
 * path, where the only way forward is to re-derive the wrap key from the
 * password and unwrap the private keys again.
 */
export function useReSignIn() {
  const { logout } = useAuth()
  const navigate = useNavigate()
  return useCallback(async () => {
    await logout()
    navigate('/login', { replace: true })
  }, [logout, navigate])
}

export function RequireAuth({ role, children }: { role?: Role; children: ReactNode }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />

  if (role && user.role !== role) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center p-6">
        <Card className="max-w-md p-6 text-center">
          <div className="mx-auto mb-3 w-fit rounded-lg bg-danger/12 p-2.5 text-danger">
            <ShieldIcon size={20} />
          </div>
          <h2 className="text-base font-semibold text-slate-100">Not authorised for this area</h2>
          <p className="mt-2 text-sm text-muted">
            This section requires a <span className="text-slate-200">{role}</span> account and you are signed in as a{' '}
            <span className="text-slate-200">{user.role}</span>.
          </p>
          <p className="mt-3 text-xs text-faint">
            Role-based access control is enforced by the server as well — this page being hidden is only the visible half.
            The attempt has been written to the audit log.
          </p>
        </Card>
      </div>
    )
  }

  return <>{children}</>
}
