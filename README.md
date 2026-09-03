# BookVault — Secure Privacy-First Library Management

**CSE447 Lab Project · Choice 2**

A library management system where every piece of patron data — reading history,
checkout records, fines, private book reviews, chat messages and profile details —
is encrypted *before* it reaches the database and decrypted only on authorised
retrieval. The Head Librarian (admin) runs the library but **cannot read patron
data**, and neither can anyone holding a dump of the database.

Every cryptographic algorithm is **implemented from scratch in plain JavaScript**.
`node:crypto`, `bcrypt`, `jose`, `crypto-js`, `elliptic` and every other crypto
package are absent from the dependency tree. The single OS primitive used is
`crypto.getRandomValues()` for entropy, isolated in `server/src/crypto/random.js`.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Express.js on Node.js 20 (ESM) |
| Database | Supabase (PostgreSQL) — stores only ciphertext, MAC tags and metadata |
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS v4 |
| Cryptography | 100% hand-written: SHA-256, HMAC-SHA256, CBC-MAC, RSA-2048 + OAEP, secp256k1 + ECIES, TOTP |
| Sessions | PostgreSQL `sessions` table + HttpOnly cookie; key material in process memory only |

Supabase is used **purely as a PostgreSQL host** through its client SDK.
`supabase.auth`, Row Level Security and Edge Functions are deliberately unused —
authentication, encryption and access control are all implemented in the Express
backend.

---

## Quick start

```bash
npm run install:all
```

```bash
npm run db:push
```

```bash
npm run seed:admin -- --username librarian --password "Vault-Admin-2026"
```

```bash
npm run dev
```

The API listens on `http://localhost:4000`, the app on `http://localhost:5173`.

**Demonstrating the project:** [docs/BookVault-Demo-Guide.tex](docs/BookVault-Demo-Guide.tex)
is a click-by-click walkthrough of every feature, how to show each of the nine
security properties, and a list of likely viva questions with short answers.
Compile it on Overleaf or with `pdflatex`.

Two accounts are already provisioned — a Head Librarian and a patron. Their
usernames, passwords and TOTP secrets are in [DEMO-ACCOUNTS.md](DEMO-ACCOUNTS.md).
On the second-factor screen, **Show current code** reveals the expected OTP while
`ENABLE_LAB_ROUTES=true`, so no authenticator app is needed for a demo.

`npm run db:push` needs `SUPABASE_ACCESS_TOKEN` and `SUPABASE_PROJECT_REF` in the
root `.env` (already configured). Alternatively paste `db/schema.sql` into the
Supabase SQL editor. **It drops and recreates every table.**

`server/.env` holds the project URL and service-role key plus the policy knobs
(`RSA_BITS`, `LOAN_DAYS`, `SESSION_IDLE_MINUTES`, `TOTP_STEP_SECONDS`, …).
See `server/.env.example`.

### Verify the cryptography

```bash
npm test
```

Runs the full vector suite: FIPS 180-4 SHA-256 digests, RFC 4231 HMAC cases,
Miller–Rabin against Carmichael numbers, RSA-OAEP round trips at the exact
190-byte boundary, secp256k1 group-law identities, ECIES tamper detection, TOTP
windows — plus a scan that fails the build if any file under `server/src/` imports
a forbidden crypto module.

`GET /api/lab/self-test` runs the same vectors live in the browser.

---

## The 9 security features

| # | Feature | Where it lives |
|---|---|---|
| 1 | Registration & login | Custom SHA-256 + 128-bit salt for passwords; RSA-encrypted user info — `crypto/password.js`, `routes/auth.js` |
| 2 | Two-factor authentication | HMAC-SHA256 TOTP as the second factor — `crypto/totp.js` |
| 3 | Encrypted user profile | Each field individually RSA-encrypted under the user's own public key — `services/records.js` |
| 4 | Key Management Module | Generation, storage, distribution and rotation of RSA + ECC key pairs — `services/keyManagement.js` |
| 5 | Encrypted posts | Checkouts, reviews and fines ECIES-encrypted before every database write — `routes/checkouts.js`, `routes/reviews.js`, `routes/fines.js` |
| 6 | MAC integrity layer | HMAC-SHA256 on records/reviews/fines/chat, CBC-MAC on the profile blob — `crypto/hmac.js`, `crypto/cbcmac.js` |
| 7 | Role-based access control | `requireRole` gates every admin path server-side; denials are audited — `middleware/auth.js` |
| 8 | Secure patron–librarian chat | RSA-encrypted bodies, HMAC tag over an ECDH shared secret, timestamp bound into the MAC for replay protection — `routes/chat.js` |
| 9 | Secure session management | 256-bit random tokens (only their hash stored), HttpOnly cookies, IP + user-agent fingerprinting, 30-minute idle timeout, single active session — `services/session.js` |

---

## Lab requirement → implementation

| # | Requirement | Satisfied by |
|---|---|---|
| 1 | Login & registration modules | F1 — `routes/auth.js` |
| 2 | All user info encrypted before storage | F1/F9 — RSA-2048 per profile field |
| 3 | Passwords hashed + salted | F1 — custom SHA-256 with a 128-bit salt |
| 4 | Two-step authentication | F1 — password, then HMAC-TOTP; the session token is issued only after both |
| 5 | Key Management Module | F10 — generation, storage, distribution, rotation, destruction |
| 6 | Create / view / edit posts, auto-encrypted | F3 borrow, F7 reviews, F5 fines, F6 vault |
| 7 | No plaintext in the database | `db/schema.sql` has no plaintext content column; verify with `/api/admin/encrypted/:table` |
| 8 | MAC for integrity & tamper detection | F6 HMAC on records, F9 CBC-MAC on the profile, F8 HMAC on chat |
| 9 | Exclusively asymmetric encryption | RSA-2048 (profile, chat) and ECIES/secp256k1 (records, reviews, fines) |
| 10 | At least two asymmetric algorithms | RSA and ECC, used for different data classes |
| 11 | RBAC — admin vs regular user | F7 — `requireRole`, enforced server-side, never in the UI alone |
| 12 | Secure session management | F9 — tokens, hashing, fingerprinting, timeouts, hijack detection |

---

## What the database actually holds

| Patron action | Crypto applied | Stored as |
|---|---|---|
| Register (profile) | RSA encrypt each field | ciphertext + CBC-MAC tag |
| Set password | SHA-256(salt ‖ password) | salt, hash (separate columns) |
| Borrow a book | ECIES encrypt the record | ciphertext + HMAC tag (+ plaintext due date/status only) |
| Return overdue | ECIES encrypt the fine | ciphertext + HMAC tag (+ plaintext amount for the admin dashboard) |
| Write a review | ECIES encrypt the text | ciphertext + HMAC tag |
| Send a chat message | RSA encrypt the body twice (recipient + sender copies) | ciphertext + HMAC tag over an ECDH secret |
| Log in | SHA-256 verify | comparison only |
| Enter the OTP | HMAC-SHA256 verify | comparison only |
| Open My Vault | HMAC verify → ECIES decrypt | in memory only |
| View the profile | CBC-MAC verify → RSA decrypt | in memory only |

The `checkouts` table deliberately has **no plaintext `book_id`**. The admin can
see that a loan exists and when it is due — never which book it is.

---

## Fine policy (F5)

| Days overdue | Rate | Extra |
|---|---|---|
| 1 – 7 | 5 BDT / day | — |
| 8 – 14 | 10 BDT / day | — |
| 15+ | 20 BDT / day | book replacement notice |

Returned 18 days late → (7 × 5) + (7 × 10) + (4 × 20) = **185 BDT** + a
replacement notice. Unpaid fines block further borrowing until cleared.

---

## Demonstrating the security properties

The app is built so the guarantees can be *shown*, not just claimed:

- **Admin blindness** — sign in as the librarian, open **Overview → What the
  librarian can see**. It renders the raw stored rows for checkouts, reviews,
  fines and chat. Opaque hex, nothing else.
- **Tamper detection** — with `ENABLE_LAB_ROUTES=true`, every vault record has a
  *simulate tampering* control. It flips one nibble of the stored ciphertext; the
  next read fails the MAC check, the row turns rose with **Tampered**, decryption
  is refused, and an `integrity_failure` audit event is written.
- **RBAC** — call an `/api/admin/*` endpoint with a patron session: `403`, and the
  attempt lands in the audit log as `rbac_denied`.
- **Session hijacking** — replay the `bv_session` cookie from another IP or
  user-agent: the session is revoked and `session_hijack_suspected` is logged.
- **Key rotation** — Security → Rotate keys. Every record is decrypted with the
  old keys, re-encrypted with the new ones, re-MACed, and the old key row is
  deleted. The report shows the per-table counts.

---

## Project layout

```
db/schema.sql                 PostgreSQL schema (ciphertext + metadata only)
docs/ARCHITECTURE.md          the binding implementation contract
scripts/apply-schema.mjs      pushes the schema through the Supabase Management API
server/src/crypto/            hand-written primitives (see below)
server/src/services/          KMM, sessions, session vault, audit, fines, record sealing
server/src/middleware/        auth, RBAC, error handling
server/src/routes/            auth, books, checkouts, fines, reviews, chat, profile, keys, admin, lab
server/scripts/seedAdmin.js   creates the Head Librarian through the normal crypto path
server/tests/crypto.test.js   the vector suite
client/src/                   React + TypeScript + Tailwind v4 front end
Proposal/                     the original project proposal
```

### `server/src/crypto/`

| File | Contents |
|---|---|
| `bytes.js` | encoding helpers, constant-time comparison, base32 |
| `random.js` | the only `getRandomValues` call in the project |
| `bigint.js` | `modPow`, extended Euclid, byte ↔ BigInt conversion |
| `sha256.js` | full FIPS 180-4: 64 rounds, message schedule, MD padding |
| `hmac.js` | RFC 2104 HMAC-SHA256 |
| `kdf.js` | counter-mode KDF / keystream over SHA-256 |
| `cbcmac.js` | CBC-MAC over 128-bit blocks with length-prefix padding |
| `rsa.js` | Miller–Rabin, key generation, OAEP + MGF1, chunked string encryption |
| `ecc.js` | secp256k1 group law, ECDH, ECIES (encrypt-then-MAC) |
| `totp.js` | HMAC-SHA256 TOTP with dynamic truncation |
| `keywrap.js` | password-derived protection for private keys (not for user data) |
| `password.js` | salted SHA-256 password hashing |

---

## Design notes worth defending

**Where do private keys live?** The KMM stores them wrapped with a key derived
from the user's password by iterated SHA-256, so a database dump yields nothing
usable. They are unwrapped at login and held in **process memory only**
(`services/sessionVault.js`), keyed by session id, and dropped on logout,
suspension or timeout. Restarting the server therefore forces everyone to sign in
again — that is the intended trade-off, and it is what makes "the admin cannot
decrypt patron data" literally true rather than a policy promise.

**Why a hash-based CBC-MAC block function?** The specification forbids symmetric
ciphers, and AES is a symmetric cipher. The 128-bit block function is therefore
`E(K, B) = SHA-256(K ‖ B)[0..16]`, chained in CBC mode from a zero IV over
length-prefixed, zero-padded blocks. The length prefix is what stops the classic
CBC-MAC extension forgery on variable-length messages.

**Why does chat store two ciphertexts?** RSA encrypts to exactly one recipient. To
let a sender re-read their own outbox, the body is encrypted a second time under
the sender's own public key. Both copies are opaque to the server; neither
weakens the other. The HMAC is computed over the recipient's copy together with
the timestamp, using a key derived by ECDH between the two parties — so the tag
proves authorship *and* pins the message to a moment in time.

**Why is `book_id` not stored in plaintext on checkouts?** Because it would hand
the entire reading history to anyone with database access, which is exactly the
threat this project exists to defeat. The cost is that returning a book requires
the patron's session to decrypt the record first — a cost worth paying.
