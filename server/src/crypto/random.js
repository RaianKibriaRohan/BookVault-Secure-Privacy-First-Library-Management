/**
 * The one and only place in this project that touches an operating-system
 * primitive. `crypto.getRandomValues` is explicitly permitted by the lab
 * specification for entropy seeding; every other cryptographic operation in
 * BookVault is written by hand.
 *
 * Note this is the Web Crypto *random source*, not node:crypto - no hashing,
 * ciphers, key generation or MACs come from here.
 */
import { bytesToHex } from './bytes.js'

const MAX_CHUNK = 65536 // getRandomValues refuses more than 64 KiB per call

export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('randomBytes: bad length')
  const out = new Uint8Array(n)
  for (let offset = 0; offset < n; offset += MAX_CHUNK) {
    const chunk = out.subarray(offset, Math.min(offset + MAX_CHUNK, n))
    globalThis.crypto.getRandomValues(chunk)
  }
  return out
}

export function randomHex(nBytes) {
  return bytesToHex(randomBytes(nBytes))
}

/**
 * A random BigInt of exactly `bits` bits: the top bit is forced so the value
 * really occupies the full width (important for RSA prime generation, where a
 * short prime would yield a modulus narrower than advertised).
 */
export function randomBigInt(bits) {
  if (bits <= 0) throw new RangeError('randomBigInt: bits must be positive')
  const bytes = randomBytes(Math.ceil(bits / 8))
  const excess = bytes.length * 8 - bits
  // Clear the bits above the requested width, then set the top bit.
  bytes[0] &= 0xff >> excess
  bytes[0] |= 0x80 >> excess
  let value = 0n
  for (const b of bytes) value = (value << 8n) | BigInt(b)
  return value
}

/** Uniform BigInt in [0, limit) by rejection sampling - no modulo bias. */
export function randomBigIntBelow(limit) {
  if (limit <= 0n) throw new RangeError('randomBigIntBelow: limit must be positive')
  const bits = limit.toString(2).length
  const byteLen = Math.ceil(bits / 8)
  const excess = byteLen * 8 - bits
  for (;;) {
    const bytes = randomBytes(byteLen)
    bytes[0] &= 0xff >> excess
    let value = 0n
    for (const b of bytes) value = (value << 8n) | BigInt(b)
    if (value < limit) return value
  }
}

/** Uniform integer in [0, maxExclusive) by rejection sampling. */
export function randomInt(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new RangeError('randomInt: bad bound')
  }
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive
  for (;;) {
    const b = randomBytes(4)
    const value = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
    if (value < limit) return value % maxExclusive
  }
}
