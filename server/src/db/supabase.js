/**
 * Supabase is used here purely as a hosted PostgreSQL instance reached through
 * its client SDK.
 *
 * Deliberately NOT used:
 *   - supabase.auth        (authentication is implemented in routes/auth.js)
 *   - Row Level Security   (access control is implemented in middleware/auth.js)
 *   - Edge Functions       (all logic runs in this Express process)
 *
 * The service-role key never leaves the server; the browser talks only to this
 * API. Because RLS is bypassed by that key, every query in this codebase is
 * responsible for its own ownership filter - see the `user_id` predicate on
 * every patron-scoped query.
 */
import { createClient } from '@supabase/supabase-js'
import config from '../config.js'

export const db = createClient(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
  global: { headers: { 'x-application-name': 'bookvault' } },
})

/** Supabase returns { data, error }; this turns an error into a thrown exception. */
export function unwrap({ data, error }, context = 'query') {
  if (error) {
    const err = new Error(`Database ${context} failed: ${error.message}`)
    err.status = 500
    err.code = 'DB_ERROR'
    err.cause = error
    throw err
  }
  return data
}
