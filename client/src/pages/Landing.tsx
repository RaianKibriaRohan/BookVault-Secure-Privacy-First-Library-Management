import { Link } from 'react-router-dom'
import { Button } from '../components/ui'

export default function Landing() {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-ink px-5">
      <div className="vault-grid pointer-events-none absolute inset-0" aria-hidden="true" />

      <main className="relative flex flex-col items-center text-center">
        <svg width="52" height="52" viewBox="0 0 32 32" aria-hidden="true">
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

        <h1 className="mt-5 text-4xl font-semibold tracking-tight text-slate-50 sm:text-5xl">BookVault</h1>

        <div className="mt-10 flex flex-col gap-3 sm:flex-row">
          <Link to="/register">
            <Button className="w-full px-6 py-2.5 sm:w-auto">Create a patron account</Button>
          </Link>
          <Link to="/login">
            <Button variant="ghost" className="w-full px-6 py-2.5 sm:w-auto">
              Sign in
            </Button>
          </Link>
        </div>
      </main>
    </div>
  )
}
