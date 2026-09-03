#!/usr/bin/env node
/**
 * Back-dates a patron's active loan so an overdue fine can be demonstrated.
 *
 *   node scripts/backdate.mjs <username> <daysOverdue>
 *   node scripts/backdate.mjs faiza 18
 *
 * Only the plaintext `due_date` mirror column is changed. That is the column
 * the server uses to calculate a fine on return, so this produces a genuine
 * fine through the normal code path - nothing is faked, and the encrypted
 * record and its HMAC tag are left untouched.
 *
 * Needs SUPABASE_ACCESS_TOKEN and SUPABASE_PROJECT_REF in the root .env.
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

if (existsSync(join(root, '.env'))) {
  for (const line of readFileSync(join(root, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim()
  }
}

const token = process.env.SUPABASE_ACCESS_TOKEN
const ref = process.env.SUPABASE_PROJECT_REF

if (!token || !ref) {
  console.error('Missing SUPABASE_ACCESS_TOKEN or SUPABASE_PROJECT_REF in the root .env.')
  process.exit(1)
}

const username = process.argv[2]
const days = Number.parseInt(process.argv[3] ?? '18', 10)

if (!username || !Number.isFinite(days) || days < 1) {
  console.error('\nUsage: node scripts/backdate.mjs <username> <daysOverdue>')
  console.error('   eg: node scripts/backdate.mjs faiza 18\n')
  process.exit(1)
}

// A username is interpolated into SQL below, so refuse anything that is not a
// plain identifier rather than trying to escape it.
if (!/^[A-Za-z0-9_.-]{1,32}$/.test(username)) {
  console.error('That username contains characters this script will not put into SQL.')
  process.exit(1)
}

const sql = async query => {
  const res = await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  })
  if (!res.ok) throw new Error(`SQL failed (${res.status}): ${await res.text()}`)
  return res.json()
}

const [user] = await sql(`select id, username from users where lower(username) = lower('${username}')`)
if (!user) {
  console.error(`\nNo account called "${username}".\n`)
  process.exit(1)
}

const active = await sql(
  `select id, due_date from checkouts where user_id = '${user.id}' and status = 'active' order by created_at`,
)

if (active.length === 0) {
  console.error(`\n"${username}" has no active loan. Borrow a book in the app first, then run this again.\n`)
  process.exit(1)
}

const updated = await sql(
  `update checkouts set due_date = current_date - ${days}
   where user_id = '${user.id}' and status = 'active'
   returning id, due_date`,
)

// Mirror of the tiered policy in server/src/services/fines.js, for the printout.
const tiers = [
  { label: 'days 1-7', from: 1, to: 7, rate: 5 },
  { label: 'days 8-14', from: 8, to: 14, rate: 10 },
  { label: 'day 15+', from: 15, to: Infinity, rate: 20 },
]
let expected = 0
const lines = []
for (const tier of tiers) {
  if (days < tier.from) break
  const n = Math.min(days, tier.to) - tier.from + 1
  if (n <= 0) continue
  expected += n * tier.rate
  lines.push(`    ${tier.label.padEnd(11)} ${String(n).padStart(2)} x ${tier.rate} BDT = ${n * tier.rate} BDT`)
}

console.log(`
  Back-dated ${updated.length} active loan(s) for "${user.username}" by ${days} days.

${lines.join('\n')}
    ${''.padEnd(11)} ${'expected total:'.padStart(9)} ${expected} BDT${days >= 15 ? ' + replacement notice' : ''}

  Now open My Vault in the app and press Return on that book.
  The fine it creates should match the total above.
`)
