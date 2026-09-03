/**
 * Time-based one-time passwords (RFC 6238 shape, HMAC-SHA256 variant) - the
 * second authentication factor.
 *
 *   OTP = DynamicTruncate( HMAC-SHA256(secret, floor(unixTime / step)) ) mod 10^6
 *
 * The proposal calls for HMAC-SHA256 rather than the RFC's default SHA-1, which
 * is why the otpauth URI advertises algorithm=SHA256.
 */
import { randomBytes } from './random.js'
import { hmacSha256 } from './hmac.js'
import { toBase32, fromBase32 } from './bytes.js'

export const DEFAULT_STEP = 30
export const DIGITS = 6

export function generateTotpSecret() {
  return toBase32(randomBytes(20)) // 160 bits, the RFC 4226 recommendation
}

function counterBytes(counter) {
  const out = new Uint8Array(8)
  let value = BigInt(counter)
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return out
}

function codeForCounter(secretBytes, counter) {
  const mac = hmacSha256(secretBytes, counterBytes(counter))
  // Dynamic truncation: the low nibble of the last byte selects a 4-byte window.
  const offset = mac[mac.length - 1] & 0x0f
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff)
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0')
}

export function totpCode(secretB32, timeMs = Date.now(), step = DEFAULT_STEP) {
  const secret = fromBase32(secretB32)
  const counter = Math.floor(timeMs / 1000 / step)
  return codeForCounter(secret, counter)
}

/**
 * Accepts the current step plus `window` steps either side, which gives the
 * 60-second acceptance window the proposal specifies at the default settings.
 * Every candidate is evaluated before returning so a wrong code always costs
 * the same time as a right one.
 */
export function verifyTotp(secretB32, code, timeMs = Date.now(), window = 1, step = DEFAULT_STEP) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) return false
  const candidate = code.trim()
  const secret = fromBase32(secretB32)
  const current = Math.floor(timeMs / 1000 / step)
  let matched = 0
  for (let offset = -window; offset <= window; offset++) {
    const expected = codeForCounter(secret, current + offset)
    let diff = 0
    for (let i = 0; i < DIGITS; i++) diff |= expected.charCodeAt(i) ^ candidate.charCodeAt(i)
    matched |= diff === 0 ? 1 : 0
  }
  return matched === 1
}

export function secondsRemaining(timeMs = Date.now(), step = DEFAULT_STEP) {
  return step - Math.floor(timeMs / 1000) % step
}

export function totpUri(secretB32, username, issuer = 'BookVault') {
  const label = encodeURIComponent(`${issuer}:${username}`)
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: 'SHA256',
    digits: String(DIGITS),
    period: String(DEFAULT_STEP),
  })
  return `otpauth://totp/${label}?${params.toString()}`
}
