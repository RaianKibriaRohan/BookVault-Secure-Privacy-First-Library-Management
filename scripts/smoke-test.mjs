#!/usr/bin/env node
/**
 * End-to-end smoke test for a running BookVault stack.
 *
 *   node scripts/smoke-test.mjs            (expects the API on :4000)
 *
 * Walks the whole product surface the way a marker would: register a patron,
 * pass both authentication factors, borrow, go overdue, return, get fined, pay,
 * review, chat with the librarian, rotate keys, prove RBAC, and prove the MAC
 * layer rejects a tampered record.
 *
 * Needs SUPABASE_ACCESS_TOKEN + SUPABASE_PROJECT_REF in the root .env to
 * back-date a checkout (the only way to produce an overdue book on demand).
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { totpCode } from '../server/src/crypto/totp.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
if (existsSync(join(root, '.env'))) {
  for (const line of readFileSync(join(root, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim()
  }
}

const BASE = process.env.BOOKVAULT_API || 'http://localhost:4000'
const PAT = process.env.SUPABASE_ACCESS_TOKEN
const REF = process.env.SUPABASE_PROJECT_REF

let pass = 0
let fail = 0
const failures = []

function ok(name, condition, extra = '') {
  if (condition) {
    pass++
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}`)
  } else {
    fail++
    failures.push(name + (extra ? ` — ${extra}` : ''))
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name}${extra ? ` — ${extra}` : ''}`)
  }
}
const section = t => console.log(`\n\x1b[1m${t}\x1b[0m`)

/** A fetch wrapper with an isolated cookie jar, so several users can be driven at once. */
function makeClient() {
  const jar = new Map()
  return async function call(method, path, body) {
    const headers = { 'Content-Type': 'application/json' }
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    for (const raw of res.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(';')
      const idx = pair.indexOf('=')
      const name = pair.slice(0, idx).trim()
      const value = pair.slice(idx + 1).trim()
      if (value === '' || /Expires=Thu, 01 Jan 1970/i.test(raw)) jar.delete(name)
      else jar.set(name, value)
    }
    const text = await res.text()
    let data
    try { data = text ? JSON.parse(text) : null } catch { data = { raw: text } }
    return { status: res.status, ok: res.ok, data }
  }
}

const sql = async query => {
  const r = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${PAT}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  })
  if (!r.ok) throw new Error(`SQL failed: ${r.status} ${await r.text()}`)
  return r.json()
}

async function signIn(call, username, password, secret) {
  const step1 = await call('POST', '/api/auth/login', { username, password })
  if (!step1.ok) throw new Error(`login failed for ${username}: ${JSON.stringify(step1.data)}`)
  const code = totpCode(secret, Date.now())
  const step2 = await call('POST', '/api/auth/verify-2fa', {
    challengeId: step1.data.challengeId,
    code,
  })
  if (!step2.ok) throw new Error(`2FA failed for ${username}: ${JSON.stringify(step2.data)}`)
  return { step1, step2 }
}

const stamp = Date.now().toString(36)
const patron = { username: `patron_${stamp}`, password: 'Correct-Horse-9!' }
const admin = { username: `librarian_${stamp}`, password: 'Vault-Admin-2026!' }

const P = makeClient()
const A = makeClient()

// ---------------------------------------------------------------------------
section('1. Service health')
{
  const r = await P('GET', '/api/health')
  ok('GET /api/health responds 200', r.status === 200, `got ${r.status}`)
}

section('2. Hand-written crypto self-test')
{
  const r = await P('GET', '/api/lab/self-test')
  ok('self-test endpoint responds', r.ok, `status ${r.status}`)
  const results = r.data?.results ?? r.data?.tests ?? []
  const failed = results.filter(t => !t.pass)
  ok(`all ${results.length} crypto vectors pass`, results.length > 0 && failed.length === 0,
    failed.map(f => f.name).join(', '))
}

section('3. Registration (F1) — salted SHA-256, RSA profile fields, key generation')
let patronTotp
{
  const t0 = Date.now()
  const r = await P('POST', '/api/auth/register', {
    username: patron.username,
    password: patron.password,
    email: 'patron@example.edu',
    phone: '+8801700000001',
    libraryCard: 'LIB-0001',
    fullName: 'Test Patron',
    address: '12 Vault Road, Dhaka',
  })
  ok('registration succeeds', r.ok, JSON.stringify(r.data).slice(0, 200))
  patronTotp = r.data?.totpSecret
  ok('TOTP secret returned exactly once', typeof patronTotp === 'string' && patronTotp.length >= 16)
  ok('key fingerprints returned', !!r.data?.fingerprints)
  console.log(`        key generation took ${Date.now() - t0} ms`)

  const validExtras = {
    email: 'someone@example.edu', phone: '+8801700000123',
    libraryCard: 'LIB-0002', fullName: 'Other Patron', address: '3 Test Lane',
  }
  const dup = await P('POST', '/api/auth/register', {
    username: patron.username, password: patron.password, ...validExtras,
  })
  ok('duplicate username rejected', !dup.ok && dup.status === 409, `status ${dup.status}`)

  const weak = await P('POST', '/api/auth/register', {
    username: `weak_${stamp}`, password: '123', ...validExtras,
  })
  ok('weak password rejected', !weak.ok && weak.status === 400, `status ${weak.status}`)

  const badEmail = await P('POST', '/api/auth/register', {
    username: `bad_${stamp}`, password: patron.password, ...validExtras, email: 'not-an-email',
  })
  ok('malformed email rejected', !badEmail.ok && badEmail.status === 400, `status ${badEmail.status}`)
}

section('4. Database holds no plaintext')
if (PAT && REF) {
  const [row] = await sql(`select email_enc, phone_enc, password_hash, profile_mac
                           from users where username = '${patron.username}'`)
  ok('email stored as ciphertext', !!row.email_enc && !row.email_enc.includes('patron@example.edu'))
  ok('phone stored as ciphertext', !!row.phone_enc && !row.phone_enc.includes('8801700000001'))
  ok('password stored as a hash, not plaintext', !row.password_hash.includes(patron.password))
  ok('profile carries a CBC-MAC tag', !!row.profile_mac && row.profile_mac.length === 32,
    `len ${row.profile_mac?.length}`)
} else {
  console.log('  SKIP  (no SUPABASE_ACCESS_TOKEN / SUPABASE_PROJECT_REF)')
}

section('5. Two-factor authentication (F1)')
{
  const bad = await P('POST', '/api/auth/login', { username: patron.username, password: 'wrong' })
  ok('wrong password rejected', !bad.ok, `status ${bad.status}`)

  const step1 = await P('POST', '/api/auth/login', { username: patron.username, password: patron.password })
  ok('correct password returns a 2FA challenge', step1.ok && step1.data.stage === '2fa')

  const badCode = await P('POST', '/api/auth/verify-2fa', { challengeId: step1.data.challengeId, code: '000000' })
  ok('wrong OTP rejected', !badCode.ok, `status ${badCode.status}`)

  const me0 = await P('GET', '/api/auth/me')
  ok('no session issued before the second factor', me0.status === 401, `status ${me0.status}`)

  const step1b = await P('POST', '/api/auth/login', { username: patron.username, password: patron.password })
  const good = await P('POST', '/api/auth/verify-2fa', {
    challengeId: step1b.data.challengeId,
    code: totpCode(patronTotp, Date.now()),
  })
  ok('correct OTP issues a session', good.ok, JSON.stringify(good.data).slice(0, 200))

  const me = await P('GET', '/api/auth/me')
  ok('/api/auth/me returns the patron', me.ok && me.data.user.username === patron.username)
  ok('role is patron', me.data?.user?.role === 'patron')
}

section('6. Catalog (F2)')
let bookId
{
  const list = await P('GET', '/api/books')
  const books = list.data?.books ?? list.data
  ok('catalog lists seeded books', Array.isArray(books) && books.length >= 15, `got ${books?.length}`)

  // Pick a title that actually has a copy on the shelf — earlier runs of this
  // script leave books on loan, so the first row is not reliably available.
  const available = books?.find(b => b.availableCopies > 0)
  ok('at least one book is available to borrow', Boolean(available))
  if (!available) {
    console.log('\nNo copies available anywhere; cannot exercise the borrow flow. Re-seed with npm run db:push.')
    process.exit(1)
  }
  bookId = available.id
  const search = await P('GET', '/api/books?q=crypt')
  const found = search.data?.books ?? search.data
  ok('search filters by title/author', Array.isArray(found) && found.length > 0 && found.length < books.length)
  const genres = await P('GET', '/api/books/genres')
  ok('genre list returned', !!genres.data)
}

section('7. Borrow → overdue → return → fine (F3, F4, F5, F6)')
let checkoutId
{
  const borrow = await P('POST', '/api/checkouts', { bookId })
  ok('borrow succeeds', borrow.ok, JSON.stringify(borrow.data).slice(0, 200))

  const again = await P('POST', '/api/checkouts', { bookId })
  ok('borrowing the same book twice is refused', !again.ok && again.status === 409, `status ${again.status}`)

  const vault = await P('GET', '/api/checkouts')
  const items = vault.data?.checkouts ?? vault.data
  ok('vault decrypts the checkout', Array.isArray(items) && items.length === 1)
  ok('decrypted record carries the book title', !!items?.[0]?.book?.title)
  ok('integrity verified', items?.[0]?.integrity === 'ok', items?.[0]?.integrity)
  checkoutId = items?.[0]?.id
  if (!checkoutId) {
    console.log('\nNo checkout was created, so the remaining sections cannot run.')
    process.exit(1)
  }

  if (PAT && REF) {
    const [enc] = await sql(`select ciphertext, hmac_tag from checkouts where id = '${checkoutId}'`)
    ok('checkout stored as ciphertext only',
      !!enc.ciphertext && !enc.ciphertext.toLowerCase().includes('crypt') && !!enc.hmac_tag)

    // back-date by 18 days -> 7*5 + 7*10 + 4*20 = 185 BDT + replacement notice
    await sql(`update checkouts set due_date = current_date - 18 where id = '${checkoutId}'`)
  }

  const ret = await P('POST', `/api/checkouts/${checkoutId}/return`, {})
  ok('return succeeds', ret.ok, JSON.stringify(ret.data).slice(0, 200))
  if (PAT && REF) {
    const amount = Number(ret.data?.fine?.amount)
    ok('18 days overdue is fined 185 BDT', amount === 185, `got ${amount}`)
    ok('replacement notice issued at 15+ days', ret.data?.fine?.replacementNotice === true)
  }

  const blocked = await P('POST', '/api/checkouts', { bookId })
  if (PAT && REF) ok('unpaid fine blocks borrowing', !blocked.ok && blocked.status === 403, `status ${blocked.status}`)

  const fines = await P('GET', '/api/fines')
  const fineList = fines.data?.fines ?? fines.data
  if (PAT && REF) {
    ok('fine record decrypts for its owner', Array.isArray(fineList) && fineList.length === 1)
    ok('fine integrity verified', fineList?.[0]?.integrity === 'ok')
    const payment = await P('POST', `/api/fines/${fineList[0].id}/pay`, {})
    ok('fine payment succeeds', payment.ok)
    const after = await P('POST', '/api/checkouts', { bookId })
    ok('borrowing unblocked after payment', after.ok, JSON.stringify(after.data).slice(0, 160))
  }
}

section('8. Private reviews (F7)')
let reviewId
{
  const eligible = await P('GET', '/api/reviews/eligible')
  const books = eligible.data?.books ?? eligible.data
  ok('returned book is review-eligible', Array.isArray(books) && books.length >= 1, `got ${books?.length}`)

  const create = await P('POST', '/api/reviews', {
    bookId,
    bookTitle: books?.[0]?.title ?? 'Applied Cryptography',
    rating: 5,
    body: 'Private note: this stays encrypted at rest.',
  })
  ok('review created', create.ok, JSON.stringify(create.data).slice(0, 200))

  const list = await P('GET', '/api/reviews')
  const reviews = list.data?.reviews ?? list.data
  ok('review decrypts for its author', Array.isArray(reviews) && reviews.length === 1)
  ok('review integrity verified', reviews?.[0]?.integrity === 'ok')
  reviewId = reviews?.[0]?.id
}

section('9. Encrypted profile + CBC-MAC (F9)')
{
  const get = await P('GET', '/api/profile')
  ok('profile decrypts', get.ok && get.data?.fields?.email === 'patron@example.edu',
    JSON.stringify(get.data).slice(0, 200))
  ok('CBC-MAC verifies', get.data?.macValid === true)

  const put = await P('PUT', '/api/profile', { phone: '+8801700000999' })
  ok('profile update succeeds', put.ok)
  const after = await P('GET', '/api/profile')
  ok('updated field round-trips', after.data?.fields?.phone === '+8801700000999')
  ok('CBC-MAC still verifies after update', after.data?.macValid === true)
}

section('10. Head Librarian account + RBAC (Feature 7, A1–A5)')
let adminTotp
{
  const r = await A('POST', '/api/auth/register', {
    username: admin.username,
    password: admin.password,
    email: 'librarian@example.edu',
    phone: '+8801700000002',
    libraryCard: 'LIB-ADMIN',
    fullName: 'Head Librarian',
    address: 'Library Building',
  })
  ok('librarian account registered', r.ok, JSON.stringify(r.data).slice(0, 160))
  adminTotp = r.data?.totpSecret
  if (PAT && REF) await sql(`update users set role = 'admin' where username = '${admin.username}'`)
  await signIn(A, admin.username, admin.password, adminTotp)

  const patronHitsAdmin = await P('GET', '/api/admin/users')
  ok('patron is refused admin endpoints', patronHitsAdmin.status === 403, `status ${patronHitsAdmin.status}`)

  const stats = await A('GET', '/api/admin/stats')
  ok('admin can read stats', stats.ok, `status ${stats.status}`)

  const users = await A('GET', '/api/admin/users')
  const userList = users.data?.users ?? users.data
  ok('admin can list patrons', Array.isArray(userList) && userList.length >= 2)
  const serialised = JSON.stringify(userList)
  ok('admin user list exposes no encrypted profile fields',
    !serialised.includes('email_enc') && !serialised.includes('patron@example.edu'))

  const enc = await A('GET', '/api/admin/encrypted/checkouts')
  const rows = enc.data?.rows ?? enc.data
  ok('admin sees checkout rows as raw ciphertext', Array.isArray(rows) && rows.length >= 1)
  ok('no decrypted book title leaks to the admin',
    !JSON.stringify(rows).includes('Applied Cryptography'))

  const adminFines = await A('GET', '/api/admin/fines')
  ok('admin fine dashboard responds', adminFines.ok)

  const audit = await A('GET', '/api/admin/audit?limit=50')
  const events = audit.data?.events ?? audit.data
  ok('audit log records events', Array.isArray(events) && events.length > 0)
  const kinds = new Set(events.map(e => e.event_type ?? e.eventType))
  ok('audit captured login + rbac denial',
    kinds.has('login') && [...kinds].some(k => String(k).includes('rbac')),
    [...kinds].join(','))
}

section('11. Secure chat (F8) — RSA + HMAC over an ECDH secret')
{
  const me = await A('GET', '/api/auth/me')
  const adminId = me.data.user.id
  const send = await P('POST', '/api/chat/messages', {
    peerId: adminId,
    body: 'Could the library acquire a copy of Serious Cryptography?',
  })
  ok('patron sends a message to the librarian', send.ok, JSON.stringify(send.data).slice(0, 200))

  const threads = await A('GET', '/api/chat/threads')
  const list = threads.data?.threads ?? threads.data
  ok('librarian sees the thread', Array.isArray(list) && list.length >= 1)

  const meP = await P('GET', '/api/auth/me')
  const inbox = await A('GET', `/api/chat/messages?peerId=${meP.data.user.id}`)
  const msgs = inbox.data?.messages ?? inbox.data
  ok('librarian decrypts the message', Array.isArray(msgs) && msgs.some(m => m.body?.includes('Serious Cryptography')))
  ok('message integrity verified', msgs?.every(m => m.integrity === 'ok'))

  const reply = await A('POST', '/api/chat/messages', { peerId: meP.data.user.id, body: 'Ordered — arriving next week.' })
  ok('librarian replies', reply.ok)
  const back = await P('GET', `/api/chat/messages?peerId=${adminId}`)
  const backMsgs = back.data?.messages ?? back.data
  ok('patron reads their own outbox and the reply',
    backMsgs?.some(m => m.direction === 'out' && m.body?.includes('Serious Cryptography')) &&
    backMsgs?.some(m => m.direction === 'in' && m.body?.includes('Ordered')))

  if (PAT && REF) {
    const [row] = await sql(`select body_for_recipient from chat_messages order by ts desc limit 1`)
    ok('chat body stored encrypted', !row.body_for_recipient.includes('Ordered'))
  }
}

section('12. Tamper detection (F6 MAC layer)')
{
  const t = await P('POST', '/api/lab/tamper', { table: 'reviews', id: reviewId })
  ok('tamper endpoint flips a ciphertext nibble', t.ok, JSON.stringify(t.data).slice(0, 160))
  const list = await P('GET', '/api/reviews')
  const reviews = list.data?.reviews ?? list.data
  const tampered = reviews?.find(r => r.id === reviewId)
  ok('MAC verification now fails', tampered?.integrity === 'tampered', tampered?.integrity)
  ok('no plaintext is returned for a tampered record', !tampered?.body && !tampered?.review?.body)
}

section('13. Key rotation (F10)')
{
  const before = await P('GET', '/api/keys')
  const v0 = before.data?.version
  const serialised = JSON.stringify(before.data)
  const leaks = ['rsa_d', 'ecc_priv', 'mac_key', 'wrapped', '"d":', 'privateKey'].filter(k => serialised.includes(k))
  ok('key info exposes fingerprints but no private material',
    before.ok && leaks.length === 0 && !!before.data?.rsa?.fingerprint, leaks.join(','))

  const wrong = await P('POST', '/api/keys/rotate', { password: 'not-the-password' })
  ok('rotation requires the correct password', !wrong.ok, `status ${wrong.status}`)

  const rot = await P('POST', '/api/keys/rotate', { password: patron.password })
  ok('key rotation succeeds', rot.ok, JSON.stringify(rot.data).slice(0, 300))
  ok('key version incremented', rot.data?.version === v0 + 1, `${v0} -> ${rot.data?.version}`)

  const profile = await P('GET', '/api/profile')
  ok('profile still decrypts under the new key', profile.ok && profile.data?.fields?.email === 'patron@example.edu')
  ok('CBC-MAC recomputed correctly', profile.data?.macValid === true)

  const checkouts = await P('GET', '/api/checkouts')
  const items = checkouts.data?.checkouts ?? checkouts.data
  ok('checkout records survive rotation', items?.some(i => i.integrity === 'ok'))

  if (PAT && REF) {
    const rows = await sql(`select count(*)::int as n from user_keys uk
                            join users u on u.id = uk.user_id
                            where u.username = '${patron.username}'`)
    ok('old key row destroyed (exactly one live version)', rows[0].n === 1, `found ${rows[0].n}`)
  }
}

section('14. Session management (Feature 9)')
{
  const logout = await P('POST', '/api/auth/logout', {})
  ok('logout succeeds', logout.ok)
  const after = await P('GET', '/api/auth/me')
  ok('session no longer valid after logout', after.status === 401, `status ${after.status}`)

  // single-session enforcement: a second login invalidates the first
  const S1 = makeClient()
  const S2 = makeClient()
  await signIn(S1, patron.username, patron.password, patronTotp)
  const alive1 = await S1('GET', '/api/auth/me')
  ok('first session alive', alive1.ok)
  await signIn(S2, patron.username, patron.password, patronTotp)
  const dead1 = await S1('GET', '/api/auth/me')
  ok('a new login revokes the previous session', dead1.status === 401, `status ${dead1.status}`)
}

// ---------------------------------------------------------------------------
console.log(`\n\x1b[1mResult\x1b[0m  ${pass} passed, ${fail} failed`)
if (fail) {
  console.log('\nFailures:')
  for (const f of failures) console.log('  - ' + f)
  process.exit(1)
}
console.log('\nAll end-to-end checks passed.')
