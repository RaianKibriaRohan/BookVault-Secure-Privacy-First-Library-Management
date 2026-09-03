import 'dotenv/config'

const num = (value, fallback) => {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

const bool = (value, fallback = false) => {
  if (value === undefined) return fallback
  return /^(1|true|yes|on)$/i.test(String(value).trim())
}

const config = Object.freeze({
  PORT: num(process.env.PORT, 4000),
  NODE_ENV: process.env.NODE_ENV ?? 'development',
  isProd: process.env.NODE_ENV === 'production',
  CLIENT_ORIGIN: process.env.CLIENT_ORIGIN ?? 'http://localhost:5173',

  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,

  // Cryptographic policy
  RSA_BITS: num(process.env.RSA_BITS, 2048),
  PASSWORD_ITERATIONS: num(process.env.PASSWORD_ITERATIONS, 1),
  KEYWRAP_ITERATIONS: num(process.env.KEYWRAP_ITERATIONS, 120000),
  TOTP_STEP_SECONDS: num(process.env.TOTP_STEP_SECONDS, 30),
  TOTP_WINDOW: num(process.env.TOTP_WINDOW, 1),

  // Library policy
  LOAN_DAYS: num(process.env.LOAN_DAYS, 14),

  // Session policy
  SESSION_IDLE_MINUTES: num(process.env.SESSION_IDLE_MINUTES, 30),
  SESSION_ABSOLUTE_HOURS: num(process.env.SESSION_ABSOLUTE_HOURS, 12),
  SESSION_COOKIE: 'bv_session',
  CHALLENGE_TTL_MS: 60_000,
  MAX_OTP_ATTEMPTS: 3,

  ENABLE_LAB_ROUTES: bool(process.env.ENABLE_LAB_ROUTES, false),
})

if (!config.SUPABASE_URL || !config.SUPABASE_SERVICE_KEY) {
  console.error(
    '\nMissing Supabase configuration.\n' +
      'Copy server/.env.example to server/.env and fill in SUPABASE_URL and\n' +
      'SUPABASE_SERVICE_KEY (Project Settings -> API -> service_role key).\n',
  )
  process.exit(1)
}

export default config
