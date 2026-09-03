import { Link, Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import { RequireAuth, useAuth } from './context/AuthContext'
import { Button, Card } from './components/ui'

import Landing from './pages/Landing'
import Register from './pages/Register'
import Login from './pages/Login'
import Catalog from './pages/Catalog'
import BookDetail from './pages/BookDetail'
import Vault from './pages/Vault'
import Reviews from './pages/Reviews'
import Chat from './pages/Chat'
import Profile from './pages/Profile'
import Security from './pages/Security'
import AdminDashboard from './pages/admin/AdminDashboard'
import AdminBooks from './pages/admin/AdminBooks'
import AdminUsers from './pages/admin/AdminUsers'
import AdminFines from './pages/admin/AdminFines'
import AdminChat from './pages/admin/AdminChat'
import AdminAudit from './pages/admin/AdminAudit'

function NotFound() {
  const { user } = useAuth()
  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Card className="max-w-md p-8 text-center">
        <div className="mono text-4xl font-semibold text-accent/70">404</div>
        <h1 className="mt-3 text-lg font-semibold text-slate-100">That shelf is empty</h1>
        <p className="mt-2 text-sm text-muted">The page you asked for does not exist.</p>
        <div className="mt-5">
          <Link to={user ? (user.role === 'admin' ? '/admin' : '/catalog') : '/'}>
            <Button>Back to {user ? 'the library' : 'the front page'}</Button>
          </Link>
        </div>
      </Card>
    </div>
  )
}

/** Sends an already-signed-in visitor to their home surface. */
function HomeGate() {
  const { user, loading } = useAuth()
  if (loading) return null
  if (user) return <Navigate to={user.role === 'admin' ? '/admin' : '/catalog'} replace />
  return <Landing />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomeGate />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/catalog" element={<Catalog />} />
        <Route path="/catalog/:id" element={<BookDetail />} />
        <Route path="/vault" element={<Vault />} />
        <Route path="/reviews" element={<Reviews />} />
        <Route path="/chat" element={<Chat />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/security" element={<Security />} />

        <Route
          path="/admin"
          element={
            <RequireAuth role="admin">
              <AdminDashboard />
            </RequireAuth>
          }
        />
        <Route
          path="/admin/books"
          element={
            <RequireAuth role="admin">
              <AdminBooks />
            </RequireAuth>
          }
        />
        <Route
          path="/admin/users"
          element={
            <RequireAuth role="admin">
              <AdminUsers />
            </RequireAuth>
          }
        />
        <Route
          path="/admin/fines"
          element={
            <RequireAuth role="admin">
              <AdminFines />
            </RequireAuth>
          }
        />
        <Route
          path="/admin/chat"
          element={
            <RequireAuth role="admin">
              <AdminChat />
            </RequireAuth>
          }
        />
        <Route
          path="/admin/audit"
          element={
            <RequireAuth role="admin">
              <AdminAudit />
            </RequireAuth>
          }
        />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}
