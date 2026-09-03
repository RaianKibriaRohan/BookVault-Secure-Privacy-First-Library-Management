/**
 * RSA-2048 from scratch: prime generation (Miller-Rabin), key generation,
 * and OAEP padding with SHA-256 / MGF1.
 *
 * Used for the data classes that are small and infrequent - profile fields and
 * chat message bodies - exactly as the proposal specifies. Bulk record data
 * goes through ECIES instead (see ecc.js).
 */
import { randomBigInt, randomBigIntBelow, randomBytes } from './random.js'
import { modPow, modInverse, gcd, lcm, bytesToBigInt, bigIntToBytes, bitLength } from './bigint.js'
import { sha256, sha256Hex } from './sha256.js'
import { utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, concatBytes, timingSafeEqual } from './bytes.js'

export const PUBLIC_EXPONENT = 65537n

const H_LEN = 32 // SHA-256 output size

// ---------------------------------------------------------------------------
// Primality
// ---------------------------------------------------------------------------

/** Odd primes below 4096, used to reject ~80% of candidates before Miller-Rabin. */
const SMALL_PRIMES = (() => {
  const limit = 4096
  const sieve = new Uint8Array(limit + 1)
  const primes = []
  for (let i = 2; i <= limit; i++) {
    if (sieve[i]) continue
    primes.push(BigInt(i))
    for (let j = i * i; j <= limit; j += i) sieve[j] = 1
  }
  return primes
})()

/**
 * Miller-Rabin probabilistic primality test.
 * Writes n-1 = 2^r * d with d odd, then checks whether each random base is a
 * witness to compositeness. With 24 independent bases the error probability is
 * below 4^-24, far beyond what key generation needs.
 */
export function isProbablePrime(n, rounds = 24) {
  if (n < 2n) return false
  for (const p of SMALL_PRIMES) {
    if (n === p) return true
    if (n % p === 0n) return false
  }

  let d = n - 1n
  let r = 0n
  while ((d & 1n) === 0n) {
    d >>= 1n
    r += 1n
  }

  witness: for (let i = 0; i < rounds; i++) {
    const a = 2n + randomBigIntBelow(n - 4n) // base in [2, n-2]
    let x = modPow(a, d, n)
    if (x === 1n || x === n - 1n) continue
    for (let j = 1n; j < r; j++) {
      x = (x * x) % n
      if (x === n - 1n) continue witness
    }
    return false
  }
  return true
}

/**
 * A random probable prime of exactly `bits` bits. The candidate has its top two
 * bits set so that p*q always reaches the full modulus width, and is forced odd.
 */
export function generatePrime(bits) {
  if (bits < 16) throw new RangeError('generatePrime: too few bits')
  for (;;) {
    let candidate = randomBigInt(bits)
    candidate |= 1n // odd
    candidate |= 1n << BigInt(bits - 1) // full width
    candidate |= 1n << BigInt(bits - 2) // so p*q has 2*bits bits

    // Walk odd candidates upward; cheaper than re-drawing full entropy.
    for (let step = 0; step < 4096; step++) {
      if (bitLength(candidate) !== bits) break
      let divisible = false
      for (const p of SMALL_PRIMES) {
        if (candidate % p === 0n) {
          divisible = true
          break
        }
      }
      if (!divisible && isProbablePrime(candidate, 24)) return candidate
      candidate += 2n
    }
  }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * OAEP with SHA-256 needs k >= 2*hLen + 2 = 66 bytes of modulus before it can
 * carry even an empty message, so anything below 528 bits cannot be padded at
 * all. The floor is set at 1024 because a 512-bit modulus is factorable on a
 * laptop and has no business in a security project; production uses 2048.
 */
export const MIN_RSA_BITS = 1024

export function generateRsaKeyPair(bits = 2048) {
  if (bits % 2 !== 0) throw new RangeError('generateRsaKeyPair: modulus size must be even')
  if (bits < MIN_RSA_BITS) {
    throw new RangeError(
      `generateRsaKeyPair: ${bits}-bit modulus is too small; OAEP-SHA256 requires at least 528 bits and this project enforces ${MIN_RSA_BITS}`,
    )
  }
  const half = bits / 2

  for (;;) {
    const p = generatePrime(half)
    let q = generatePrime(half)

    // p and q must differ substantially: if |p-q| is small, n can be factored
    // by Fermat's method in a handful of steps.
    let guard = 0
    while ((p > q ? p - q : q - p) < 1n << BigInt(half - 100)) {
      q = generatePrime(half)
      if (++guard > 32) break
    }
    if (p === q) continue

    const n = p * q
    if (bitLength(n) !== bits) continue

    const lambda = lcm(p - 1n, q - 1n)
    if (gcd(PUBLIC_EXPONENT, lambda) !== 1n) continue

    const d = modInverse(PUBLIC_EXPONENT, lambda)
    if (d < 1n << BigInt(half)) continue // reject a suspiciously small private exponent

    return { n, e: PUBLIC_EXPONENT, d, p, q }
  }
}

export function serializeRsaPublic(pub) {
  return { n: pub.n.toString(16), e: pub.e.toString(16) }
}

export function deserializeRsaPublic(obj) {
  return { n: BigInt('0x' + obj.n), e: BigInt('0x' + obj.e) }
}

export function rsaPublicFingerprint(pub) {
  const digest = sha256Hex(pub.n.toString(16) + pub.e.toString(16))
  return (digest.slice(0, 16).toUpperCase().match(/.{4}/g) ?? []).join(' ')
}

export function modulusBits(pub) {
  return bitLength(pub.n)
}

// ---------------------------------------------------------------------------
// OAEP (PKCS#1 v2.2) with SHA-256 and MGF1
// ---------------------------------------------------------------------------

/** MGF1: a variable-length mask built by hashing (seed || counter). */
function mgf1(seed, length) {
  const out = new Uint8Array(length)
  const counter = new Uint8Array(4)
  let offset = 0
  let i = 0
  while (offset < length) {
    counter[0] = (i >>> 24) & 0xff
    counter[1] = (i >>> 16) & 0xff
    counter[2] = (i >>> 8) & 0xff
    counter[3] = i & 0xff
    const block = sha256(concatBytes(seed, counter))
    const take = Math.min(H_LEN, length - offset)
    out.set(block.subarray(0, take), offset)
    offset += take
    i++
  }
  return out
}

const L_HASH = sha256(new Uint8Array(0)) // hash of the empty label

export function maxMessageLength(pub) {
  const k = Math.ceil(bitLength(pub.n) / 8)
  return k - 2 * H_LEN - 2
}

function oaepEncode(message, k) {
  const maxLen = k - 2 * H_LEN - 2
  if (maxLen < 0) {
    throw new Error(`RSA_MODULUS_TOO_SMALL: OAEP-SHA256 needs at least ${2 * H_LEN + 2} bytes of modulus, got ${k}`)
  }
  if (message.length > maxLen) {
    throw new Error(`RSA_MESSAGE_TOO_LONG: ${message.length} > ${maxLen}`)
  }
  // DB = lHash || PS(zeros) || 0x01 || M
  const db = new Uint8Array(k - H_LEN - 1)
  db.set(L_HASH, 0)
  db[db.length - message.length - 1] = 0x01
  db.set(message, db.length - message.length)

  const seed = randomBytes(H_LEN)
  const dbMask = mgf1(seed, db.length)
  const maskedDb = new Uint8Array(db.length)
  for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i]

  const seedMask = mgf1(maskedDb, H_LEN)
  const maskedSeed = new Uint8Array(H_LEN)
  for (let i = 0; i < H_LEN; i++) maskedSeed[i] = seed[i] ^ seedMask[i]

  // EM = 0x00 || maskedSeed || maskedDB
  return concatBytes(new Uint8Array([0x00]), maskedSeed, maskedDb)
}

function oaepDecode(em, k) {
  // Every failure raises the same opaque error: distinguishing "bad leading
  // byte" from "bad lHash" is how padding-oracle attacks get their signal.
  const fail = () => {
    throw new Error('RSA_OAEP_DECODE_ERROR')
  }
  if (em.length !== k || k < 2 * H_LEN + 2) fail()

  let bad = em[0] !== 0x00 ? 1 : 0

  const maskedSeed = em.subarray(1, 1 + H_LEN)
  const maskedDb = em.subarray(1 + H_LEN)

  const seedMask = mgf1(maskedDb, H_LEN)
  const seed = new Uint8Array(H_LEN)
  for (let i = 0; i < H_LEN; i++) seed[i] = maskedSeed[i] ^ seedMask[i]

  const dbMask = mgf1(seed, maskedDb.length)
  const db = new Uint8Array(maskedDb.length)
  for (let i = 0; i < maskedDb.length; i++) db[i] = maskedDb[i] ^ dbMask[i]

  if (!timingSafeEqual(db.subarray(0, H_LEN), L_HASH)) bad |= 1

  let index = -1
  for (let i = H_LEN; i < db.length; i++) {
    if (db[i] === 0x01 && index === -1) {
      index = i
    } else if (db[i] !== 0x00 && index === -1) {
      bad |= 1
    }
  }
  if (index === -1) bad |= 1
  if (bad) fail()

  return db.slice(index + 1)
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------

export function rsaEncrypt(pub, msgBytes) {
  const k = Math.ceil(bitLength(pub.n) / 8)
  const em = oaepEncode(msgBytes instanceof Uint8Array ? msgBytes : utf8ToBytes(msgBytes), k)
  const m = bytesToBigInt(em)
  if (m >= pub.n) throw new Error('RSA_MESSAGE_TOO_LONG')
  const c = modPow(m, pub.e, pub.n)
  return bigIntToBytes(c, k)
}

export function rsaDecrypt(priv, ctBytes) {
  const k = Math.ceil(bitLength(priv.n) / 8)
  if (ctBytes.length !== k) throw new Error('RSA_OAEP_DECODE_ERROR')
  const c = bytesToBigInt(ctBytes)
  if (c >= priv.n) throw new Error('RSA_OAEP_DECODE_ERROR')
  const m = modPow(c, priv.d, priv.n)
  return oaepDecode(bigIntToBytes(m, k), k)
}

/**
 * OAEP caps a single RSA-2048 operation at 190 bytes, so longer strings are
 * split into chunks, each encrypted independently, and the hex blocks joined
 * with '.'. Chunking happens on the *byte* array, and the pieces are rejoined
 * before UTF-8 decoding, so a multi-byte character straddling a boundary
 * survives intact.
 */
export function rsaEncryptString(pub, str) {
  const bytes = utf8ToBytes(String(str))
  const chunkSize = maxMessageLength(pub)
  const parts = []
  if (bytes.length === 0) {
    parts.push(bytesToHex(rsaEncrypt(pub, bytes)))
  } else {
    for (let i = 0; i < bytes.length; i += chunkSize) {
      parts.push(bytesToHex(rsaEncrypt(pub, bytes.subarray(i, i + chunkSize))))
    }
  }
  return parts.join('.')
}

export function rsaDecryptString(priv, blob) {
  if (typeof blob !== 'string' || blob.length === 0) throw new Error('RSA_OAEP_DECODE_ERROR')
  const chunks = blob.split('.').map(hex => rsaDecrypt(priv, hexToBytes(hex)))
  return bytesToUtf8(concatBytes(...chunks))
}
