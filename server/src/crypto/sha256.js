/**
 * SHA-256 - complete FIPS 180-4 implementation.
 *
 * Merkle-Damgard construction: the message is padded with 0x80, then zeros,
 * then its length in bits as a 64-bit big-endian integer, so the total is a
 * multiple of 64 bytes. Each block runs the 64-round compression function over
 * a message schedule of 64 words.
 *
 * This is the foundation of every other primitive in BookVault: HMAC, the KDF,
 * the CBC-MAC block function, RSA-OAEP's MGF1, ECIES key derivation, TOTP and
 * password hashing all call into here.
 */
import { utf8ToBytes, bytesToHex } from './bytes.js'

// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

// First 32 bits of the fractional parts of the square roots of the first 8 primes.
const H0 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
])

const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0

export function sha256(input) {
  const msg = typeof input === 'string' ? utf8ToBytes(input) : input
  const bitLen = BigInt(msg.length) * 8n

  // Padding: 0x80, zeros, 8-byte big-endian bit length.
  const withOne = msg.length + 1
  const padded = new Uint8Array(Math.ceil((withOne + 8) / 64) * 64)
  padded.set(msg, 0)
  padded[msg.length] = 0x80
  const lenOffset = padded.length - 8
  let len = bitLen
  for (let i = 7; i >= 0; i--) {
    padded[lenOffset + i] = Number(len & 0xffn)
    len >>= 8n
  }

  const H = H0.slice()
  const W = new Uint32Array(64)

  for (let block = 0; block < padded.length; block += 64) {
    // Message schedule.
    for (let t = 0; t < 16; t++) {
      const i = block + t * 4
      W[t] = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0
      const s1 = (rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0
    }

    let [a, b, c, d, e, f, g, h] = H

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      const temp2 = (S0 + maj) >>> 0

      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }

    H[0] = (H[0] + a) >>> 0
    H[1] = (H[1] + b) >>> 0
    H[2] = (H[2] + c) >>> 0
    H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0
    H[5] = (H[5] + f) >>> 0
    H[6] = (H[6] + g) >>> 0
    H[7] = (H[7] + h) >>> 0
  }

  const out = new Uint8Array(32)
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (H[i] >>> 24) & 0xff
    out[i * 4 + 1] = (H[i] >>> 16) & 0xff
    out[i * 4 + 2] = (H[i] >>> 8) & 0xff
    out[i * 4 + 3] = H[i] & 0xff
  }
  return out
}

export function sha256Hex(input) {
  return bytesToHex(sha256(input))
}
