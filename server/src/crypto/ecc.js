/**
 * secp256k1 elliptic-curve arithmetic and ECIES, from scratch.
 *
 * ECIES protects the high-volume, per-record data: checkout records, fine
 * records and private reviews. Compared with RSA it produces far smaller
 * ciphertext for the same security level and encrypts arbitrary lengths in one
 * pass, which is exactly why the proposal splits the workload this way.
 *
 * Curve:  y^2 = x^3 + 7  over F_p,  p = 2^256 - 2^32 - 977
 */
import { modPow, modInverse, bytesToBigInt, bigIntToBytes } from './bigint.js'
import { randomBigIntBelow } from './random.js'
import { sha256, sha256Hex } from './sha256.js'
import { hmacSha256, hmacSha256Hex } from './hmac.js'
import { kdf, keystream } from './kdf.js'
import { utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, concatBytes, timingSafeEqual } from './bytes.js'

export const CURVE = Object.freeze({
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  name: 'secp256k1',
})

export const G = Object.freeze({ x: CURVE.Gx, y: CURVE.Gy })

const mod = v => ((v % CURVE.p) + CURVE.p) % CURVE.p

// ---------------------------------------------------------------------------
// Group law (affine coordinates; null is the point at infinity)
// ---------------------------------------------------------------------------

export function isOnCurve(P) {
  if (P === null) return true
  if (typeof P?.x !== 'bigint' || typeof P?.y !== 'bigint') return false
  if (P.x < 0n || P.x >= CURVE.p || P.y < 0n || P.y >= CURVE.p) return false
  return mod(P.y * P.y) === mod(P.x * P.x * P.x + CURVE.b)
}

export function pointDouble(P) {
  if (P === null) return null
  if (P.y === 0n) return null // the tangent is vertical: 2P = infinity
  // lambda = (3x^2 + a) / 2y, with a = 0 on secp256k1
  const lambda = mod(3n * P.x * P.x * modInverse(2n * P.y, CURVE.p))
  const x = mod(lambda * lambda - 2n * P.x)
  const y = mod(lambda * (P.x - x) - P.y)
  return { x, y }
}

export function pointAdd(P, Q) {
  if (P === null) return Q
  if (Q === null) return P
  if (P.x === Q.x) {
    // Same x: either P == Q (double) or Q == -P (sum is the point at infinity).
    if (mod(P.y + Q.y) === 0n) return null
    return pointDouble(P)
  }
  const lambda = mod((Q.y - P.y) * modInverse(mod(Q.x - P.x), CURVE.p))
  const x = mod(lambda * lambda - P.x - Q.x)
  const y = mod(lambda * (P.x - x) - P.y)
  return { x, y }
}

export function pointNegate(P) {
  return P === null ? null : { x: P.x, y: mod(-P.y) }
}

/** Double-and-add scalar multiplication. */
export function scalarMult(k, P) {
  if (typeof k !== 'bigint') throw new TypeError('scalarMult: scalar must be a BigInt')
  if (P !== null && !isOnCurve(P)) throw new Error('POINT_NOT_ON_CURVE')
  let scalar = ((k % CURVE.n) + CURVE.n) % CURVE.n
  if (scalar === 0n) return null
  let result = null
  let addend = P
  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, addend)
    addend = pointDouble(addend)
    scalar >>= 1n
  }
  return result
}

export function publicFromPrivate(priv) {
  const pub = scalarMult(priv, G)
  if (pub === null) throw new Error('ECC_BAD_PRIVATE_KEY')
  return pub
}

export function generateEccKeyPair() {
  // Private scalar in [1, n-1].
  const priv = 1n + randomBigIntBelow(CURVE.n - 1n)
  return { priv, pub: publicFromPrivate(priv) }
}

// ---------------------------------------------------------------------------
// Point encoding
// ---------------------------------------------------------------------------

/** SEC1 compressed form: 0x02/0x03 depending on the parity of y, then x. */
export function compressPoint(P) {
  if (P === null) throw new Error('ECC_POINT_AT_INFINITY')
  const prefix = (P.y & 1n) === 0n ? 0x02 : 0x03
  return bytesToHex(concatBytes(new Uint8Array([prefix]), bigIntToBytes(P.x, 32)))
}

/**
 * Recover y from x. Since p = 3 (mod 4), the square root is x^((p+1)/4);
 * the prefix picks which of the two roots was meant.
 */
export function decompressPoint(hex) {
  const bytes = typeof hex === 'string' ? hexToBytes(hex) : hex
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
    throw new Error('ECC_BAD_POINT_ENCODING')
  }
  const x = bytesToBigInt(bytes.subarray(1))
  const alpha = mod(x * x * x + CURVE.b)
  let y = modPow(alpha, (CURVE.p + 1n) / 4n, CURVE.p)
  if (mod(y * y) !== alpha) throw new Error('POINT_NOT_ON_CURVE')
  const wantOdd = bytes[0] === 0x03
  if (((y & 1n) === 1n) !== wantOdd) y = mod(-y)
  const P = { x, y }
  if (!isOnCurve(P)) throw new Error('POINT_NOT_ON_CURVE')
  return P
}

export function eccPublicFingerprint(pub) {
  const digest = sha256Hex(compressPoint(pub))
  return (digest.slice(0, 16).toUpperCase().match(/.{4}/g) ?? []).join(' ')
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

/**
 * The shared secret is the *hash* of the compressed shared point, not the raw
 * x-coordinate. Raw coordinates are not uniformly distributed over the byte
 * space, so hashing is what makes the output safe to feed to a KDF.
 *
 * The peer's public key is validated first: accepting an off-curve point would
 * open the classic invalid-curve attack that leaks the private scalar.
 */
export function ecdh(priv, pub) {
  if (!isOnCurve(pub) || pub === null) throw new Error('POINT_NOT_ON_CURVE')
  const shared = scalarMult(priv, pub)
  if (shared === null) throw new Error('ECDH_DEGENERATE')
  return sha256(utf8ToBytes(compressPoint(shared)))
}

// ---------------------------------------------------------------------------
// ECIES - encrypt then MAC
// ---------------------------------------------------------------------------

const ECIES_VERSION = 0x01
const ECIES_INFO = 'BookVault-ECIES-v1'
const ECIES_STREAM_INFO = 'ECIES-STREAM'

/**
 * Blob layout (hex):  0x01 || compressed R (33) || ciphertext (n) || tag (32)
 *
 *   R = rG for a fresh ephemeral scalar r      (so every encryption is unique)
 *   S = ECDH(r, recipientPublicKey)
 *   K = KDF(S, 'BookVault-ECIES-v1', 64) -> kEnc = K[0..32], kMac = K[32..64]
 *   C = M XOR keystream(kEnc, 'ECIES-STREAM', |M|)
 *   T = HMAC-SHA256(kMac, R || C)
 *
 * Encrypt-then-MAC: the tag covers the ephemeral key and the ciphertext, so a
 * modified record is rejected before any decryption is attempted.
 */
export function eciesEncrypt(pub, msgBytes) {
  const message = msgBytes instanceof Uint8Array ? msgBytes : utf8ToBytes(String(msgBytes))
  const ephemeral = generateEccKeyPair()
  const shared = ecdh(ephemeral.priv, pub)
  const K = kdf(shared, ECIES_INFO, 64)
  const kEnc = K.subarray(0, 32)
  const kMac = K.subarray(32, 64)

  const stream = keystream(kEnc, ECIES_STREAM_INFO, message.length)
  const ct = new Uint8Array(message.length)
  for (let i = 0; i < message.length; i++) ct[i] = message[i] ^ stream[i]

  const rBytes = hexToBytes(compressPoint(ephemeral.pub))
  const tag = hmacSha256(kMac, concatBytes(rBytes, ct))

  return bytesToHex(concatBytes(new Uint8Array([ECIES_VERSION]), rBytes, ct, tag))
}

export function eciesDecrypt(priv, blob) {
  if (typeof blob !== 'string' || blob.length % 2 !== 0) throw new Error('BAD_ECIES_BLOB')
  let bytes
  try {
    bytes = hexToBytes(blob)
  } catch {
    throw new Error('BAD_ECIES_BLOB')
  }
  if (bytes.length < 1 + 33 + 32 || bytes[0] !== ECIES_VERSION) throw new Error('BAD_ECIES_BLOB')

  const rBytes = bytes.subarray(1, 34)
  const ct = bytes.subarray(34, bytes.length - 32)
  const tag = bytes.subarray(bytes.length - 32)

  let R
  try {
    R = decompressPoint(rBytes)
  } catch {
    throw new Error('BAD_ECIES_BLOB')
  }

  const shared = ecdh(priv, R)
  const K = kdf(shared, ECIES_INFO, 64)
  const kEnc = K.subarray(0, 32)
  const kMac = K.subarray(32, 64)

  // Verify before decrypting - the whole point of encrypt-then-MAC.
  const expected = hmacSha256(kMac, concatBytes(rBytes, ct))
  if (!timingSafeEqual(expected, tag)) throw new Error('MAC_FAILURE')

  const stream = keystream(kEnc, ECIES_STREAM_INFO, ct.length)
  const out = new Uint8Array(ct.length)
  for (let i = 0; i < ct.length; i++) out[i] = ct[i] ^ stream[i]
  return out
}

export function eciesEncryptString(pub, str) {
  return eciesEncrypt(pub, utf8ToBytes(String(str)))
}

export function eciesDecryptString(priv, blob) {
  return bytesToUtf8(eciesDecrypt(priv, blob))
}

export function serializeEccPublic(pub) {
  return { x: pub.x.toString(16), y: pub.y.toString(16) }
}

export function deserializeEccPublic(obj) {
  return { x: BigInt('0x' + obj.x), y: BigInt('0x' + obj.y) }
}
