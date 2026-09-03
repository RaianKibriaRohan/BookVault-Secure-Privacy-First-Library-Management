/**
 * Big-integer helpers for RSA and elliptic-curve arithmetic.
 * Native BigInt supplies +, *, % and comparison; everything modular is here.
 */

/** Modular exponentiation by square-and-multiply (right to left). */
export function modPow(base, exp, mod) {
  if (mod <= 0n) throw new RangeError('modPow: modulus must be positive')
  if (mod === 1n) return 0n
  if (exp < 0n) throw new RangeError('modPow: negative exponent')
  let result = 1n
  let b = ((base % mod) + mod) % mod
  let e = exp
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod
    b = (b * b) % mod
    e >>= 1n
  }
  return result
}

/** Extended Euclid: returns { g, x, y } with a*x + b*y = g = gcd(a, b). */
export function egcd(a, b) {
  let [oldR, r] = [a, b]
  let [oldS, s] = [1n, 0n]
  let [oldT, t] = [0n, 1n]
  while (r !== 0n) {
    const q = oldR / r
    ;[oldR, r] = [r, oldR - q * r]
    ;[oldS, s] = [s, oldS - q * s]
    ;[oldT, t] = [t, oldT - q * t]
  }
  return { g: oldR, x: oldS, y: oldT }
}

export function modInverse(a, m) {
  if (m <= 0n) throw new RangeError('modInverse: modulus must be positive')
  const aa = ((a % m) + m) % m
  const { g, x } = egcd(aa, m)
  if (g !== 1n) throw new Error('modInverse: value is not invertible')
  return ((x % m) + m) % m
}

export function gcd(a, b) {
  let x = a < 0n ? -a : a
  let y = b < 0n ? -b : b
  while (y) {
    ;[x, y] = [y, x % y]
  }
  return x
}

export function lcm(a, b) {
  return (a / gcd(a, b)) * b
}

export function bytesToBigInt(bytes) {
  let value = 0n
  for (const b of bytes) value = (value << 8n) | BigInt(b)
  return value
}

/** Big-endian, left zero-padded to exactly `length` bytes. */
export function bigIntToBytes(value, length) {
  if (value < 0n) throw new RangeError('bigIntToBytes: negative value')
  const out = new Uint8Array(length)
  let v = value
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v !== 0n) throw new RangeError('bigIntToBytes: value does not fit in ' + length + ' bytes')
  return out
}

export function bitLength(value) {
  if (value === 0n) return 0
  return value.toString(2).length
}

export function byteLength(value) {
  return Math.ceil(bitLength(value) / 8)
}
