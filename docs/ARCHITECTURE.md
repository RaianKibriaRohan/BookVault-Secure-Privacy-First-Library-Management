# BookVault — Implementation Contract

Single source of truth for module signatures, data formats and the REST API.
Every file in `server/` and `client/` must conform to this document exactly.

- Runtime: Node.js 20 (ESM, `"type": "module"`), Express 4.
- Database: Supabase Postgres via `@supabase/supabase-js` (service-role key,
  server-side only). `supabase.auth`, RLS and Edge Functions are NOT used.
- Frontend: React 18 + TypeScript + Vite + Tailwind CSS v4 (`@tailwindcss/vite`).
- **Cryptography is 100% hand-written.** `node:crypto` and every third-party
  crypto package are forbidden. The ONLY permitted OS primitive is
  `globalThis.crypto.getRandomValues()` (entropy seeding), used exclusively
  inside `server/src/crypto/random.js`.

---

## 0. Conventions

- Binary data in memory: `Uint8Array`. Never Node `Buffer` in crypto code.
- Binary data at rest / on the wire: lowercase hex strings.
- Big integers: native `BigInt`.
- All crypto functions are synchronous and pure unless noted.
- Errors thrown by route handlers use `httpError(status, code, message)` from
  `server/src/middleware/errors.js`.

---

## 1. `server/src/crypto/` — hand-written primitives

### 1.1 `bytes.js`
```js
export function utf8ToBytes(str)            // -> Uint8Array
export function bytesToUtf8(bytes)          // -> string
export function bytesToHex(bytes)           // -> string (lowercase)
export function hexToBytes(hex)             // -> Uint8Array (throws on odd/invalid)
export function concatBytes(...arrays)      // -> Uint8Array
export function xorBytes(a, b)              // -> Uint8Array (length = min)
export function timingSafeEqual(a, b)       // -> boolean, constant time
export function timingSafeEqualHex(a, b)    // -> boolean
export function toBase32(bytes)             // -> string (RFC 4648, no padding)
export function fromBase32(str)             // -> Uint8Array
```

### 1.2 `random.js`
```js
export function randomBytes(n)              // getRandomValues, chunked at 65536
export function randomHex(nBytes)           // -> hex string
export function randomBigInt(bits)          // -> BigInt with top bit set
export function randomBigIntBelow(limit)    // -> BigInt in [0, limit)
export function randomInt(maxExclusive)     // -> Number, rejection sampled
```

### 1.3 `sha256.js` — full FIPS 180-4 implementation
64 rounds, K/H constants computed or literal, Merkle–Damgård padding.
```js
export function sha256(input)               // Uint8Array|string -> Uint8Array(32)
export function sha256Hex(input)            // -> hex string
```
Must satisfy: `sha256Hex('abc')` =
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`,
`sha256Hex('')` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 1.4 `hmac.js` — HMAC-SHA256, block size 64
`HMAC(K,m) = H((K'⊕opad) || H((K'⊕ipad) || m))`
```js
export function hmacSha256(key, message)    // (Uint8Array|string, ...) -> Uint8Array(32)
export function hmacSha256Hex(key, message) // -> hex
export function verifyHmac(key, message, tagHex)  // -> boolean (constant time)
```
Test vector (RFC 4231 #1): key = 20 × 0x0b, msg = `"Hi There"` →
`b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`.

### 1.5 `kdf.js` — counter-mode KDF over SHA-256
`T_i = SHA256(be32(i) || secret || utf8(info))`, concatenated, truncated.
```js
export function kdf(secretBytes, info, lengthBytes)   // -> Uint8Array
export function keystream(keyBytes, info, lengthBytes) // -> Uint8Array (kdf alias)
```

### 1.6 `cbcmac.js` — CBC-MAC over 128-bit blocks (F9 profile integrity)
The project forbids symmetric ciphers, so the block function is a keyed
one-way compression instead of AES:
`E(K, B) = first 16 bytes of SHA256(K || B)`.
Chaining: `C_0 = IV(zeros)`, `C_i = E(K, C_{i-1} ⊕ B_i)`, tag = `C_last`.
Length-prefix padding: message is prefixed with a big-endian 8-byte length,
then zero-padded to a 16-byte multiple (prevents length-extension forgery).
```js
export function cbcMac(key, message)        // -> Uint8Array(16)
export function cbcMacHex(key, message)     // -> hex (32 chars)
export function verifyCbcMac(key, message, tagHex)  // -> boolean
```

### 1.7 `bigint.js`
```js
export function modPow(base, exp, mod)      // square-and-multiply
export function modInverse(a, m)            // extended Euclid, throws if none
export function egcd(a, b)                  // -> { g, x, y }
export function bytesToBigInt(bytes)
export function bigIntToBytes(value, length) // left zero-padded, throws if too big
export function bitLength(value)
export function gcd(a, b)
```

### 1.8 `rsa.js` — RSA-2048 from scratch
- Prime generation: random odd candidate → small-prime sieve (primes < 4096) →
  Miller–Rabin, 24 rounds (`isProbablePrime`).
- `e = 65537n`, `d = e⁻¹ mod λ(n)` where `λ = lcm(p-1, q-1)`.
- Padding: **OAEP** with SHA-256 and MGF1 (`hLen = 32`, `k = 256`,
  max message = `k − 2·hLen − 2` = 190 bytes).
```js
export function generateRsaKeyPair(bits = 2048)  // -> { n, e, d, p, q } BigInts
export function isProbablePrime(n, rounds = 24)
export function generatePrime(bits)
export function rsaEncrypt(pub, msgBytes)   // pub {n,e}; <=190 bytes -> Uint8Array(256)
export function rsaDecrypt(priv, ctBytes)   // priv {n,d} -> Uint8Array
export function rsaEncryptString(pub, str)  // chunks of 190B, hex blocks joined by '.'
export function rsaDecryptString(priv, blob)// -> string
export function rsaPublicFingerprint(pub)   // sha256Hex(n||e).slice(0,16), grouped 4-4-4-4
export function serializeRsaPublic(pub)     // -> { n: hex, e: hex }
export function deserializeRsaPublic(o)     // -> { n: BigInt, e: BigInt }
```

### 1.9 `ecc.js` — secp256k1 + ECIES from scratch
Curve: `p = 2²⁵⁶−2³²−977`, `a = 0`, `b = 7`, standard `G`, order `n`.
Affine arithmetic with modular inversion (Fermat or extended Euclid).
```js
export const CURVE                          // { p, a, b, Gx, Gy, n }
export function pointAdd(P, Q)              // P,Q: {x,y}|null (null = point at infinity)
export function pointDouble(P)
export function scalarMult(k, P)            // double-and-add
export function isOnCurve(P)
export function generateEccKeyPair()        // -> { priv: BigInt, pub: {x,y} }
export function publicFromPrivate(priv)     // -> {x,y}
export function ecdh(priv, pub)             // -> Uint8Array(32) = sha256(compressed(S))
export function compressPoint(P)            // -> hex (33 bytes: 02/03 || x)
export function decompressPoint(hex)        // -> {x,y}   (sqrt via x^((p+1)/4))
export function eciesEncrypt(pub, msgBytes) // -> hex blob
export function eciesDecrypt(priv, blob)    // -> Uint8Array (throws 'MAC_FAILURE')
export function eciesEncryptString(pub, str)
export function eciesDecryptString(priv, blob)
export function eccPublicFingerprint(pub)
```
**ECIES blob layout** (hex of): `0x01 || compressed R (33B) || ct (nB) || tag (32B)`
where `R = rG` (ephemeral), `S = ECDH(r, pub)`,
`K = kdf(S, 'BookVault-ECIES-v1', 64)` → `kEnc = K[0..32]`, `kMac = K[32..64]`,
`ct = msg ⊕ keystream(kEnc, 'ECIES-STREAM', msg.length)`,
`tag = HMAC-SHA256(kMac, compressedR || ct)`.

### 1.10 `totp.js` — HMAC-based OTP (F1, second factor)
```js
export function generateTotpSecret()             // -> base32 string (20 random bytes)
export function totpCode(secretB32, timeMs, step = 30)  // -> 6-digit string
export function verifyTotp(secretB32, code, timeMs, window = 1)  // ±1 step ⇒ 60s window
export function totpUri(secretB32, username, issuer = 'BookVault')
export function secondsRemaining(timeMs, step = 30)
```
`OTP = DT(HMAC-SHA256(secret, be64(floor(t/step)))) mod 10⁶`, zero-padded to 6.

### 1.11 `keywrap.js` — private-key protection (NOT user-data encryption)
User records are always protected with RSA/ECC. This module exists only so
that private keys and the TOTP secret are useless in a database dump.
```js
export function deriveWrapKey(password, saltHex, iterations = 120000) // -> Uint8Array(32)
export function wrap(wrapKey, plaintextBytes)   // -> hex: keystream XOR + HMAC tag
export function unwrap(wrapKey, blob)           // -> Uint8Array, throws 'WRAP_MAC_FAILURE'
export function wrapString(wrapKey, str)
export function unwrapString(wrapKey, blob)
```
Blob layout: `nonce(16) || ct(n) || tag(32)`,
`stream = kdf(wrapKey || nonce, 'BookVault-KeyWrap-v1', n)`,
`tag = HMAC-SHA256(wrapKey, nonce || ct)`.

### 1.12 `password.js`
```js
export function hashPassword(password)              // -> { salt, hash } hex, 128-bit salt
export function hashPasswordWithSalt(password, salt)// -> hash hex
export function verifyPassword(password, salt, hash)// -> boolean (constant time)
```
`hash = SHA-256(salt || password)` per the proposal, iterated `PASSWORD_ITERATIONS`
(default 1, configurable) — the stored form is `salt:hash` across two columns.

### 1.13 `index.js`
Re-exports every symbol above.

---

## 2. `server/src/services/`

### 2.1 `keyManagement.js` — the Key Management Module (Security Feature 4)
```js
export function generateKeyBundle(rsaBits)     // -> { rsa:{n,e,d}, ecc:{priv,pub}, macKey:Uint8Array }
export async function storeKeyBundle(userId, version, bundle, wrapKey)
export async function loadPublicKeys(userId)   // -> { version, rsa:{n,e}, ecc:{x,y}, fingerprints }
export async function loadPrivateKeys(userId, wrapKey)  // -> { version, rsa:{n,e,d}, ecc:{priv,pub}, macKey }
export async function listKeyVersions(userId)
export async function rotateKeys(userId, wrapKey, onStep) // -> rotation report
```
`rotateKeys` (F10): generate new bundle → for every checkout, fine, review
(ECIES) and every profile field + chat copy (RSA): verify MAC → decrypt with old
key → re-encrypt with new key → recompute MAC → write back → insert new
`user_keys` row → **delete the old row** (old keys permanently destroyed) →
bump `users.key_version` → revoke all other sessions → audit-log it.

### 2.2 `sessionVault.js` — process-memory key cache
Private key material NEVER returns to the database in usable form and is never
written to disk. It lives in a `Map` keyed by session id, populated at login.
```js
export function putMaterial(sessionId, material)  // { wrapKey, rsa, ecc, macKey, keyVersion }
export function getMaterial(sessionId)
export function dropMaterial(sessionId)
export function dropUser(userId)
export function putChallenge(id, challenge)       // pending 2FA, 60s TTL
export function takeChallenge(id)
export function stats()                            // { sessions, challenges }
```

### 2.3 `session.js` — Security Feature 9
```js
export async function createSession(user, req)   // -> { token, session }
export async function validateSession(token, req) // -> { session, user } | throws
export async function touchSession(sessionId)
export async function revokeSession(sessionId, reason)
export async function revokeAllForUser(userId, reason, exceptId)
export function fingerprintIp(req)                // sha256Hex(ip).slice(0,32)
export function fingerprintUa(req)
```
Rules: 256-bit random token (`randomHex(32)`), only `sha256Hex(token)` stored;
HttpOnly + SameSite=Lax cookie named `bv_session`; 30-minute idle timeout
(`last_active_at`); 12-hour absolute expiry; IP + UA fingerprint mismatch →
revoke + audit `session_hijack_suspected`; single active session per user
(creating one revokes the rest).

### 2.4 `audit.js`
```js
export async function audit(req, { userId, username, eventType, outcome, detail })
```
Never throws; failures are logged to stderr only.

### 2.5 `fines.js`
```js
export function computeFine(daysOverdue)
// -> { amount, daysOverdue, replacementNotice, breakdown: [{ tier, days, rate, subtotal }] }
```
Tiers: days 1–7 → 5 BDT/day; days 8–14 → 10 BDT/day; day 15+ → 20 BDT/day and
`replacementNotice = true`. 18 days ⇒ 7×5 + 7×10 + 4×20 = **185 BDT**.
```js
export function daysBetween(dueDateISO, returnedAtISO)  // ceil, min 0
```

### 2.6 `records.js` — seal/open helper used by every encrypted table
```js
export function sealEcc(eccPub, macKey, obj, domain)
// -> { ciphertext, hmac_tag }   tag = HMAC(macKey, domain || ciphertext)
export function openEcc(eccPriv, macKey, row, domain)
// -> { data, integrity: 'ok' | 'tampered' | 'undecryptable' }
export function sealProfile(rsaPub, macKey, fields)  // -> { encFields, profile_mac }
export function openProfile(rsaPriv, macKey, userRow)// -> { fields, macValid }
```
Order for the profile CBC-MAC: `email|phone|library_card|full_name|address`
(each ciphertext, joined by `\n`, domain-prefixed with `BookVault-Profile-v1`).

---

## 3. `server/src/middleware/`

- `errors.js` → `httpError(status, code, message)`, `asyncHandler(fn)`,
  `errorHandler(err, req, res, next)` → `{ error: { code, message } }`.
- `auth.js` →
  - `requireAuth` — validates cookie, attaches `req.user`, `req.session`.
  - `requireKeys` — additionally attaches `req.keys` from the session vault;
    responds `409 KEYS_LOCKED` ("please sign in again") when absent.
  - `requireRole(...roles)` — RBAC gate (Security Feature 7).
  - `requirePatron` = `requireRole('patron')`, `requireAdmin` = `requireRole('admin')`.
  - Suspended accounts are rejected with `403 ACCOUNT_SUSPENDED`.

---

## 4. REST API (`/api`)

All responses JSON. Auth via `bv_session` HttpOnly cookie; client uses
`credentials: 'include'`.

### Auth — `routes/auth.js`
| Method | Path | Access | Body → Response |
|---|---|---|---|
| POST | `/api/auth/register` | public | `{username,password,email,phone,libraryCard,fullName,address}` → `{ok,userId,totpSecret,totpUri,fingerprints}` |
| POST | `/api/auth/login` | public | `{username,password}` → `{stage:'2fa',challengeId,expiresIn:60}` |
| POST | `/api/auth/verify-2fa` | public | `{challengeId,code}` → sets cookie, `{user}` |
| POST | `/api/auth/logout` | auth | → `{ok:true}` |
| GET | `/api/auth/me` | auth | → `{user,session:{expiresAt,idleTimeoutMin,ip},keysUnlocked}` |
| POST | `/api/auth/challenge-code` | public | dev only (`ENABLE_LAB_ROUTES`) `{challengeId}` → `{code,secondsRemaining}` |

`user` shape: `{ id, username, role, status, keyVersion, createdAt, lastLoginAt }`.
Registration performs, in order: validate → hash password (salt + custom
SHA-256) → derive wrap key → KMM generates RSA-2048 + ECC + MAC key → wrap
privates → RSA-encrypt every profile field → CBC-MAC the profile → insert.
Login step 1 verifies the password only; the TOTP secret and unwrapped keys are
held in a 60-second in-memory challenge. A session token is issued **only**
after step 2 succeeds. Failed attempts increment `failed_logins` and are audited.

### Catalog — `routes/books.js`
| Method | Path | Access |
|---|---|---|
| GET | `/api/books?q=&genre=&availability=` | auth |
| GET | `/api/books/genres` | auth |
| GET | `/api/books/:id` | auth |
| POST | `/api/books` | admin |
| PATCH | `/api/books/:id` | admin |
| DELETE | `/api/books/:id` | admin |

### Checkouts — `routes/checkouts.js`
| Method | Path | Access | Notes |
|---|---|---|---|
| POST | `/api/checkouts` | patron | `{bookId}` → blocked with `403 FINES_OUTSTANDING` when unpaid fines exist; `409 NO_COPIES`; `409 ALREADY_BORROWED`. Decrements `available_copies`, due in `LOAN_DAYS` (14). |
| GET | `/api/checkouts` | patron | decrypts all own records; each item `{id,book:{...},checkoutDate,dueDate,status,daysLeft,overdueDays,projectedFine,integrity}` |
| POST | `/api/checkouts/:id/return` | patron | verifies HMAC → decrypts → increments copies → on overdue creates an encrypted fine → `{returned,fine|null}` |

### Fines — `routes/fines.js`
`GET /api/fines` (patron, decrypted + `summary{outstanding,paid,total}`),
`POST /api/fines/:id/pay` (patron, simulated payment → `status='paid'`).

### Reviews — `routes/reviews.js`
`GET /api/reviews`, `POST /api/reviews` `{bookId,bookTitle,rating,body}`,
`PATCH /api/reviews/:id`, `DELETE /api/reviews/:id` — patron only, ECIES + HMAC.
`GET /api/reviews/eligible` → books the patron has returned and not yet reviewed.

### Chat — `routes/chat.js`
`GET /api/chat/threads` — patron: the librarian; admin: every patron with a
message, newest first, with unread counts.
`GET /api/chat/messages?peerId=` → `[{id,direction,body,ts,integrity,read}]`.
`POST /api/chat/messages` `{peerId,body}` → double RSA-encrypt (recipient +
sender copies) and HMAC with the ECDH shared secret over `ct || ts`.
Replay/tamper: recompute the HMAC on read; mismatched rows are returned with
`integrity:'tampered'` and no plaintext.

### Profile — `routes/profile.js`
`GET /api/profile` → `{fields,macValid,keyVersion}`;
`PUT /api/profile` → re-encrypts each changed field, recomputes the CBC-MAC.

### Keys — `routes/keys.js`
`GET /api/keys` → `{version,rsa:{fingerprint,modulusBits},ecc:{fingerprint,curve},createdAt,history}`;
`POST /api/keys/rotate` `{password}` → `{version,report:{checkouts,fines,reviews,chat,profile}}`.

### Admin — `routes/admin.js` (all `requireAdmin`)
`GET /api/admin/stats`, `GET /api/admin/users`,
`PATCH /api/admin/users/:id/status` `{status}`,
`GET /api/admin/fines`, `GET /api/admin/audit?event=&outcome=&limit=`,
`GET /api/admin/encrypted/:table` (`checkouts|reviews|fines|chat_messages`) —
returns raw ciphertext exactly as stored, proving the admin sees only opaque
blobs.

### Lab — `routes/lab.js` (only mounted when `ENABLE_LAB_ROUTES=true`)
`GET /api/lab/self-test` → runs the crypto test vectors and returns results.
`POST /api/lab/tamper` `{table,id}` → flips one hex nibble of a stored
ciphertext so the MAC-failure path can be demonstrated live.
`GET /api/lab/raw/:table/:id` → the raw stored row.

---

## 5. Frontend (`client/`)

Vite + React 18 + TS. Tailwind v4 via `@tailwindcss/vite` — `src/index.css`
starts with `@import "tailwindcss";` and defines the theme with `@theme`.
Dev server proxies `/api` → `http://localhost:4000`.

Routes:
`/` landing · `/register` · `/login` · `/catalog` · `/catalog/:id` ·
`/vault` · `/reviews` · `/chat` · `/profile` · `/security` ·
`/admin` · `/admin/books` · `/admin/users` · `/admin/fines` · `/admin/chat` ·
`/admin/audit`.

`src/lib/api.ts` exports a typed `api` object with one method per endpoint,
always `credentials: 'include'`, unwrapping `{error:{code,message}}` into a
thrown `ApiError`. `src/context/AuthContext.tsx` holds `{user, loading, login,
verify2fa, logout, refresh}` and guards routes with `<RequireAuth role?>`.

Visual language: dark, calm, "vault" aesthetic — deep slate background,
emerald accent for verified integrity, amber for overdue, rose for tampered.
Every screen that displays decrypted data shows an integrity badge
(`Verified` / `Tampered`) so the MAC layer is visible in the UI.

---

## 6. File manifest (exact paths + exports)

### Server
```
server/src/config.js                 default export `config`
server/src/db/supabase.js            export { db }            (supabase client)
server/src/middleware/errors.js      httpError, asyncHandler, errorHandler, notFound
server/src/middleware/auth.js        requireAuth, requireKeys, requireRole, requireAdmin, requirePatron
server/src/services/sessionVault.js  putMaterial, getMaterial, dropMaterial, dropUser,
                                     putChallenge, takeChallenge, stats
server/src/services/session.js       createSession, validateSession, touchSession,
                                     revokeSession, revokeAllForUser, fingerprintIp, fingerprintUa
server/src/services/audit.js         audit
server/src/services/fines.js         computeFine, daysBetween, FINE_TIERS
server/src/services/keyManagement.js generateKeyBundle, storeKeyBundle, loadPublicKeys,
                                     loadPrivateKeys, listKeyVersions, rotateKeys
server/src/services/records.js       sealEcc, openEcc, sealProfile, openProfile, PROFILE_FIELDS
server/src/routes/{auth,books,checkouts,fines,reviews,chat,profile,keys,admin,lab}.js
                                     each: `export default router`
server/src/index.js                  express bootstrap, mounts /api/*
server/scripts/seedAdmin.js          CLI: creates the Head Librarian account
server/tests/crypto.test.js          `node tests/crypto.test.js`, exit code 1 on failure
```

### Client
```
client/src/main.tsx
client/src/App.tsx                   routes + <RequireAuth>
client/src/index.css                 @import "tailwindcss"; + @theme tokens
client/src/vite-env.d.ts
client/src/lib/api.ts                export { api, ApiError }  + all TS types
client/src/lib/format.ts             fmtDate, fmtBDT, daysUntil, relativeTime, cx
client/src/context/AuthContext.tsx   export { AuthProvider, useAuth, RequireAuth }
client/src/components/Layout.tsx     default export Layout (sidebar + topbar + <Outlet/>)
client/src/components/ui.tsx         Button, Card, Badge, IntegrityBadge, Spinner,
                                     EmptyState, Field, Input, Textarea, Select, Modal,
                                     Stat, PageHeader, Toast/useToast
client/src/pages/Landing.tsx         default export Landing
client/src/pages/Register.tsx        default export Register
client/src/pages/Login.tsx           default export Login
client/src/pages/Catalog.tsx         default export Catalog
client/src/pages/BookDetail.tsx      default export BookDetail
client/src/pages/Vault.tsx           default export Vault
client/src/pages/Reviews.tsx         default export Reviews
client/src/pages/Chat.tsx            default export Chat
client/src/pages/Profile.tsx         default export Profile
client/src/pages/Security.tsx        default export Security
client/src/pages/admin/AdminDashboard.tsx  default export AdminDashboard
client/src/pages/admin/AdminBooks.tsx      default export AdminBooks
client/src/pages/admin/AdminUsers.tsx      default export AdminUsers
client/src/pages/admin/AdminFines.tsx      default export AdminFines
client/src/pages/admin/AdminChat.tsx       default export AdminChat
client/src/pages/admin/AdminAudit.tsx      default export AdminAudit
```

### `client/src/lib/api.ts` — exact method surface
```ts
api.auth.register(payload)            api.auth.login(username, password)
api.auth.verify2fa(challengeId, code) api.auth.logout()
api.auth.me()                         api.auth.challengeCode(challengeId)   // lab only
api.books.list(params?)               api.books.get(id)
api.books.genres()                    api.books.create(b) / update(id,b) / remove(id)
api.checkouts.list()                  api.checkouts.borrow(bookId)
api.checkouts.return(id)
api.fines.list()                      api.fines.pay(id)
api.reviews.list()                    api.reviews.eligible()
api.reviews.create(r)                 api.reviews.update(id,r) / remove(id)
api.chat.threads()                    api.chat.messages(peerId)
api.chat.send(peerId, body)
api.profile.get()                     api.profile.update(fields)
api.keys.get()                        api.keys.rotate(password)
api.admin.stats()                     api.admin.users()
api.admin.setUserStatus(id, status)   api.admin.fines()
api.admin.audit(params?)              api.admin.encrypted(table)
api.lab.selfTest()                    api.lab.tamper(table, id)
```
Every method returns a Promise of the documented payload and throws `ApiError`
(`{ status, code, message }`) on a non-2xx response.

### Shared visual tokens (`index.css`)
```
--color-ink        #060a13   page background
--color-surface    #0e1524   cards
--color-surface-2  #16203a   raised
--color-line       #22304f   borders
--color-accent     #34d399   emerald: verified / safe
--color-accent-2   #60a5fa   blue: informational
--color-warn       #fbbf24   amber: overdue / fines
--color-danger     #fb7185   rose: tampered / failure
--color-muted      #93a4c4   secondary text
```
Font stack: `ui-sans-serif, system-ui, "Segoe UI", Inter, sans-serif`;
monospace for every ciphertext/hash display: `ui-monospace, "Cascadia Code", monospace`.
