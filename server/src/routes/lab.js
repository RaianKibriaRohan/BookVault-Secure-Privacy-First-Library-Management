/**
 * Demonstration endpoints, mounted only when ENABLE_LAB_ROUTES=true.
 *
 * These exist so the security properties can be *shown* during a demo rather
 * than merely asserted. They are deliberately unavailable in a hardened
 * deployment - /tamper in particular is a controlled attack on the database.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth } from '../middleware/auth.js'
import { audit } from '../services/audit.js'
import { sha256Hex } from '../crypto/sha256.js'
import { hmacSha256Hex } from '../crypto/hmac.js'
import { cbcMacHex } from '../crypto/cbcmac.js'
import { generateRsaKeyPair, rsaEncryptString, rsaDecryptString, isProbablePrime } from '../crypto/rsa.js'
import {
  generateEccKeyPair,
  eciesEncryptString,
  eciesDecryptString,
  scalarMult,
  isOnCurve,
  CURVE,
  G,
} from '../crypto/ecc.js'
import { totpCode, verifyTotp } from '../crypto/totp.js'
import { deriveWrapKey, wrapString, unwrapString } from '../crypto/keywrap.js'

const router = Router()

// A 1024-bit demo key generated once, so the self-test stays fast on repeat runs.
let demoRsa = null
const demoEcc = generateEccKeyPair()

/**
 * GET /api/lab/self-test
 * Runs the published test vectors against our hand-written implementations.
 * Unauthenticated on purpose: a marker should be able to hit it directly.
 */
router.get(
  '/self-test',
  asyncHandler(async (req, res) => {
    const results = []
    const check = (name, fn, expected) => {
      const started = Date.now()
      let actual
      let pass = false
      try {
        actual = fn()
        pass = expected === undefined ? actual === true : actual === expected
      } catch (err) {
        actual = `threw: ${err.message}`
      }
      results.push({
        name,
        expected: expected === undefined ? 'true' : String(expected).slice(0, 80),
        actual: String(actual).slice(0, 80),
        pass,
        ms: Date.now() - started,
      })
    }

    check(
      'SHA-256("abc") - FIPS 180-4',
      () => sha256Hex('abc'),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
    check(
      'SHA-256("") - FIPS 180-4',
      () => sha256Hex(''),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
    check(
      'HMAC-SHA256 - RFC 4231 case 1',
      () => hmacSha256Hex(new Uint8Array(20).fill(0x0b), 'Hi There'),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    )
    check(
      'HMAC-SHA256 - RFC 4231 case 2',
      () => hmacSha256Hex('Jefe', 'what do ya want for nothing?'),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    )
    check('CBC-MAC is deterministic', () => cbcMacHex('k', 'profile blob') === cbcMacHex('k', 'profile blob'))
    check('CBC-MAC detects a single flipped bit', () => cbcMacHex('k', 'profile blob') !== cbcMacHex('k', 'profile bloc'))
    check('Miller-Rabin rejects Carmichael numbers', () =>
      [561n, 1105n, 1729n, 2465n, 2821n, 6601n, 8911n].every(n => !isProbablePrime(n)))
    check('Miller-Rabin accepts known primes', () => [7919n, 104729n, 1299709n].every(n => isProbablePrime(n)))
    check('secp256k1 generator is on the curve', () => isOnCurve(G))
    check('secp256k1 order: nG = point at infinity', () => scalarMult(CURVE.n, G) === null)
    check('RSA-OAEP round trip', () => {
      if (!demoRsa) demoRsa = generateRsaKeyPair(1024)
      const message = 'patron@example.edu'
      return rsaDecryptString(demoRsa, rsaEncryptString(demoRsa, message)) === message
    })
    check('RSA-OAEP is randomised', () => {
      if (!demoRsa) demoRsa = generateRsaKeyPair(1024)
      return rsaEncryptString(demoRsa, 'x') !== rsaEncryptString(demoRsa, 'x')
    })
    check('ECIES round trip', () => {
      const message = 'Borrowed: Nineteen Eighty-Four'
      return eciesDecryptString(demoEcc.priv, eciesEncryptString(demoEcc.pub, message)) === message
    })
    check('ECIES rejects a tampered ciphertext', () => {
      const blob = eciesEncryptString(demoEcc.pub, 'record')
      const flipped = blob.slice(0, 90) + (blob[90] === 'a' ? 'b' : 'a') + blob.slice(91)
      try {
        eciesDecryptString(demoEcc.priv, flipped)
        return false
      } catch (err) {
        return err.message === 'MAC_FAILURE'
      }
    })
    check('TOTP code is stable inside its 30-second step', () => {
      const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
      const base = 1735689600000
      return totpCode(secret, base) === totpCode(secret, base + 29_000)
    })
    check('TOTP accepts the adjacent step and rejects a distant one', () => {
      const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
      const base = 1735689600000
      return verifyTotp(secret, totpCode(secret, base - 30_000), base) && !verifyTotp(secret, totpCode(secret, base + 300_000), base)
    })
    check('Key wrap rejects the wrong password', () => {
      const good = deriveWrapKey('right', 'aa'.repeat(16), 500)
      const bad = deriveWrapKey('wrong', 'aa'.repeat(16), 500)
      const blob = wrapString(good, 'private-key')
      if (unwrapString(good, blob) !== 'private-key') return false
      try {
        unwrapString(bad, blob)
        return false
      } catch (err) {
        return err.message === 'WRAP_MAC_FAILURE'
      }
    })

    const failed = results.filter(r => !r.pass)
    res.json({
      verdict: failed.length === 0 ? 'all vectors pass' : `${failed.length} of ${results.length} failed`,
      passed: results.length - failed.length,
      total: results.length,
      results,
      note: 'Every algorithm above is implemented by hand in server/src/crypto - node:crypto is not imported anywhere in this project.',
    })
  }),
)

const TAMPERABLE = {
  checkouts: { column: 'ciphertext', owner: 'user_id' },
  reviews: { column: 'ciphertext', owner: 'user_id' },
  fines: { column: 'ciphertext', owner: 'user_id' },
  chat_messages: { column: 'body_for_recipient', owner: 'recipient_id' },
}

/**
 * POST /api/lab/tamper - flip one hex nibble of a stored ciphertext.
 *
 * This simulates an attacker with write access to the database. The next read
 * of that record fails its MAC check, the UI shows "Tampered", decryption is
 * refused, and an integrity_failure event is written to the audit log.
 */
router.post(
  '/tamper',
  requireAuth,
  asyncHandler(async (req, res) => {
    const table = String(req.body?.table ?? '')
    const id = String(req.body?.id ?? '')
    const spec = TAMPERABLE[table]
    if (!spec) throw httpError(400, 'VALIDATION_ERROR', 'That table cannot be tampered with here.')

    const row = unwrap(
      await db.from(table).select(`id, ${spec.owner}, ${spec.column}`).eq('id', id).maybeSingle(),
      'tamper read',
    )
    if (!row || row[spec.owner] !== req.user.id) throw httpError(404, 'NOT_FOUND', 'No such record of yours.')

    const original = row[spec.column]
    const index = Math.min(80, original.length - 1)
    const flipped = original.slice(0, index) + (original[index] === 'a' ? 'b' : 'a') + original.slice(index + 1)

    unwrap(await db.from(table).update({ [spec.column]: flipped }).eq('id', id).select('id').single(), 'tamper write')

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'lab_tamper',
      outcome: 'warning',
      detail: `demo: flipped one nibble of ${table}.${spec.column} for record ${id}`,
    })

    res.json({
      ok: true,
      table,
      id,
      changedAt: index,
      before: original.slice(Math.max(0, index - 8), index + 9),
      after: flipped.slice(Math.max(0, index - 8), index + 9),
      note: 'Reload the record - its MAC will now fail and decryption will be refused.',
    })
  }),
)

router.get(
  '/raw/:table/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const table = String(req.params.table)
    const spec = TAMPERABLE[table]
    if (!spec) throw httpError(404, 'NOT_FOUND', 'That table is not available here.')
    const row = unwrap(await db.from(table).select('*').eq('id', req.params.id).maybeSingle(), 'raw read')
    if (!row || row[spec.owner] !== req.user.id) throw httpError(404, 'NOT_FOUND', 'No such record of yours.')
    res.json({ table, row })
  }),
)

export default router
