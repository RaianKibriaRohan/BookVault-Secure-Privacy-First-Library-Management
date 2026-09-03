/**
 * BookVault API.
 *
 * Express bootstrap: middleware, route mounting, error handling.
 * All authentication, encryption and access control lives in this process -
 * Supabase is only a database (see db/supabase.js).
 */
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

import config from './config.js'
import { notFound, errorHandler } from './middleware/errors.js'
import { stats as vaultStats } from './services/sessionVault.js'

import authRoutes from './routes/auth.js'
import bookRoutes from './routes/books.js'
import checkoutRoutes from './routes/checkouts.js'
import fineRoutes from './routes/fines.js'
import reviewRoutes from './routes/reviews.js'
import chatRoutes from './routes/chat.js'
import profileRoutes from './routes/profile.js'
import keyRoutes from './routes/keys.js'
import adminRoutes from './routes/admin.js'
import labRoutes from './routes/lab.js'

const app = express()

// Behind a proxy the client IP arrives in x-forwarded-for; the session
// fingerprint depends on reading it correctly.
app.set('trust proxy', 1)
app.disable('x-powered-by')

app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use(
  cors({
    origin: config.CLIENT_ORIGIN,
    credentials: true, // the session cookie must be allowed to travel
  }),
)

app.use((req, res, next) => {
  const started = Date.now()
  res.on('finish', () => {
    if (req.originalUrl.startsWith('/api')) {
      const status = res.statusCode
      const colour = status >= 500 ? 31 : status >= 400 ? 33 : 32
      console.log(`\x1b[${colour}m${status}\x1b[0m ${req.method} ${req.originalUrl} ${Date.now() - started}ms`)
    }
  })
  next()
})

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'bookvault',
    uptimeSeconds: Math.round(process.uptime()),
    vault: vaultStats(),
    policy: {
      rsaBits: config.RSA_BITS,
      curve: 'secp256k1',
      loanDays: config.LOAN_DAYS,
      sessionIdleMinutes: config.SESSION_IDLE_MINUTES,
      totpStepSeconds: config.TOTP_STEP_SECONDS,
      labRoutes: config.ENABLE_LAB_ROUTES,
    },
  })
})

app.use('/api/auth', authRoutes)
app.use('/api/books', bookRoutes)
app.use('/api/checkouts', checkoutRoutes)
app.use('/api/fines', fineRoutes)
app.use('/api/reviews', reviewRoutes)
app.use('/api/chat', chatRoutes)
app.use('/api/profile', profileRoutes)
app.use('/api/keys', keyRoutes)
app.use('/api/admin', adminRoutes)
if (config.ENABLE_LAB_ROUTES) app.use('/api/lab', labRoutes)

app.use('/api', notFound)
app.use(errorHandler)

app.listen(config.PORT, () => {
  console.log(`
  BookVault API  ->  http://localhost:${config.PORT}
  client origin  ->  ${config.CLIENT_ORIGIN}
  crypto         ->  hand-written SHA-256 / HMAC / CBC-MAC / RSA-${config.RSA_BITS} / secp256k1 ECIES / TOTP
  routes         ->  /api/auth /api/books /api/checkouts /api/fines /api/reviews
                     /api/chat /api/profile /api/keys /api/admin${config.ENABLE_LAB_ROUTES ? ' /api/lab' : ''}
`)
})
