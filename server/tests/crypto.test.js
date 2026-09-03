#!/usr/bin/env node
/**
 * BookVault cryptography test suite.
 *
 *   npm test
 *
 * No test framework - a tiny harness lives at the top of this file, so the
 * suite has exactly the same dependency footprint as the code it tests (none).
 * Exits non-zero on the first failing assertion count.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative } from 'node:path'

import {
  utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, concatBytes, timingSafeEqual,
  toBase32, fromBase32,
} from '../src/crypto/bytes.js'
import { randomBytes, randomBigInt, randomBigIntBelow, randomInt } from '../src/crypto/random.js'
import { sha256, sha256Hex } from '../src/crypto/sha256.js'
import { hmacSha256Hex, verifyHmac } from '../src/crypto/hmac.js'
import { kdf, keystream } from '../src/crypto/kdf.js'
import { cbcMacHex, verifyCbcMac } from '../src/crypto/cbcmac.js'
import { modPow, modInverse, gcd, bytesToBigInt, bigIntToBytes } from '../src/crypto/bigint.js'
import {
  generateRsaKeyPair, isProbablePrime, generatePrime, rsaEncrypt, rsaDecrypt,
  rsaEncryptString, rsaDecryptString, rsaPublicFingerprint, maxMessageLength,
} from '../src/crypto/rsa.js'
import {
  CURVE, G, pointAdd, pointDouble, pointNegate, scalarMult, isOnCurve,
  generateEccKeyPair, publicFromPrivate, ecdh, compressPoint, decompressPoint,
  eciesEncryptString, eciesDecryptString, eccPublicFingerprint,
} from '../src/crypto/ecc.js'
import { generateTotpSecret, totpCode, verifyTotp, totpUri, secondsRemaining } from '../src/crypto/totp.js'
import { deriveWrapKey, wrapString, unwrapString } from '../src/crypto/keywrap.js'
import { hashPassword, hashPasswordWithSalt, verifyPassword } from '../src/crypto/password.js'

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
let passed = 0
let failed = 0
const failures = []
let suite = ''

const green = s => `\x1b[32m${s}\x1b[0m`
const red = s => `\x1b[31m${s}\x1b[0m`
const dim = s => `\x1b[2m${s}\x1b[0m`

function describe(name, fn) {
  suite = name
  const started = Date.now()
  console.log(`\n\x1b[1m${name}\x1b[0m`)
  fn()
  console.log(dim(`  ${Date.now() - started} ms`))
}

function it(name, fn) {
  try {
    fn()
    passed++
    console.log(`  ${green('ok')}   ${name}`)
  } catch (err) {
    failed++
    failures.push(`${suite} > ${name}: ${err.message}`)
    console.log(`  ${red('FAIL')} ${name}\n       ${err.message}`)
  }
}

function assert(condition, message = 'assertion failed') {
  if (!condition) throw new Error(message)
}

function equal(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`${message || 'values differ'}\n       expected: ${String(expected).slice(0, 120)}\n       actual:   ${String(actual).slice(0, 120)}`)
  }
}

function throws(fn, expectedMessage) {
  try {
    fn()
  } catch (err) {
    if (expectedMessage && err.message !== expectedMessage) {
      throw new Error(`threw "${err.message}", expected "${expectedMessage}"`)
    }
    return
  }
  throw new Error('expected the call to throw, but it returned normally')
}

// ---------------------------------------------------------------------------
describe('bytes / encoding', () => {
  it('UTF-8 round trip covers 1-, 2-, 3- and 4-byte code points', () => {
    const samples = ['', 'abc', 'café', 'naïve résumé', '漢字テスト', '🔐📚🇧🇩', 'a🔐b漢c']
    for (const s of samples) equal(bytesToUtf8(utf8ToBytes(s)), s, `round trip of ${JSON.stringify(s)}`)
  })

  it('UTF-8 byte lengths are correct', () => {
    equal(utf8ToBytes('a').length, 1)
    equal(utf8ToBytes('é').length, 2)
    equal(utf8ToBytes('漢').length, 3)
    equal(utf8ToBytes('🔐').length, 4)
  })

  it('hex encoding round trips and rejects malformed input', () => {
    const bytes = Uint8Array.from([0x00, 0x0f, 0xff, 0xa5])
    equal(bytesToHex(bytes), '000fffa5')
    assert(timingSafeEqual(hexToBytes('000fffa5'), bytes))
    throws(() => hexToBytes('abc'))
    throws(() => hexToBytes('zz'))
  })

  it('concatBytes joins in order', () => {
    equal(bytesToHex(concatBytes(Uint8Array.from([1, 2]), Uint8Array.from([3]))), '010203')
  })

  it('timingSafeEqual matches only identical arrays', () => {
    assert(timingSafeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 3])))
    assert(!timingSafeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 4])))
    assert(!timingSafeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2])))
  })

  it('base32 matches RFC 4648 vectors and round trips', () => {
    equal(toBase32(utf8ToBytes('f')), 'MY')
    equal(toBase32(utf8ToBytes('fo')), 'MZXQ')
    equal(toBase32(utf8ToBytes('foobar')), 'MZXW6YTBOI')
    for (let i = 0; i < 20; i++) {
      const raw = randomBytes(20)
      assert(timingSafeEqual(fromBase32(toBase32(raw)), raw), 'base32 round trip')
    }
  })
})

describe('random (the only OS primitive in the project)', () => {
  it('randomBytes returns the requested length, including across the 64 KiB chunk limit', () => {
    for (const n of [0, 1, 32, 65535, 65536, 70000]) equal(randomBytes(n).length, n)
  })

  it('randomBytes output differs between calls', () => {
    assert(bytesToHex(randomBytes(32)) !== bytesToHex(randomBytes(32)))
  })

  it('randomBigInt produces exactly the requested bit width', () => {
    for (const bits of [8, 64, 256, 1024]) {
      for (let i = 0; i < 5; i++) equal(randomBigInt(bits).toString(2).length, bits, `${bits}-bit width`)
    }
  })

  it('randomBigIntBelow stays inside its bound', () => {
    const limit = 1000n
    for (let i = 0; i < 200; i++) {
      const value = randomBigIntBelow(limit)
      assert(value >= 0n && value < limit, `${value} out of range`)
    }
  })

  it('randomInt covers its range without exceeding it', () => {
    const seen = new Set()
    for (let i = 0; i < 500; i++) {
      const value = randomInt(10)
      assert(Number.isInteger(value) && value >= 0 && value < 10)
      seen.add(value)
    }
    assert(seen.size >= 8, 'distribution looks degenerate')
  })
})

describe('SHA-256 (FIPS 180-4)', () => {
  it('matches the published one-block digest', () => {
    equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('matches the published empty-string digest', () => {
    equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('matches the published two-block digest', () => {
    equal(
      sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    )
  })

  it('matches the published 1,000,000 x "a" digest', () => {
    equal(sha256Hex('a'.repeat(1_000_000)), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
  })

  it('handles every padding boundary (55, 56, 63, 64, 119, 120 bytes)', () => {
    // 55 and 56 straddle the point where the length no longer fits in the
    // final block, forcing an extra block to be appended.
    const digests = new Set()
    for (const n of [54, 55, 56, 57, 63, 64, 65, 119, 120, 121]) {
      const digest = sha256Hex('a'.repeat(n))
      equal(digest.length, 64, `digest length for ${n} bytes`)
      digests.add(digest)
    }
    equal(digests.size, 10, 'every input length must give a distinct digest')
  })

  it('accepts Uint8Array and string input interchangeably', () => {
    equal(sha256Hex('abc'), bytesToHex(sha256(utf8ToBytes('abc'))))
  })
})

describe('HMAC-SHA256 (RFC 4231)', () => {
  it('case 1 - 20-byte key', () => {
    equal(
      hmacSha256Hex(new Uint8Array(20).fill(0x0b), 'Hi There'),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    )
  })

  it('case 2 - short ASCII key', () => {
    equal(
      hmacSha256Hex('Jefe', 'what do ya want for nothing?'),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    )
  })

  it('case 3 - 20-byte key, 50-byte message', () => {
    equal(
      hmacSha256Hex(new Uint8Array(20).fill(0xaa), new Uint8Array(50).fill(0xdd)),
      '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    )
  })

  it('case 4 - key longer than the 64-byte block is hashed first', () => {
    equal(
      hmacSha256Hex(new Uint8Array(131).fill(0xaa), 'Test Using Larger Than Block-Size Key - Hash Key First'),
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    )
  })

  it('verifyHmac accepts a good tag and rejects a bad one', () => {
    const tag = hmacSha256Hex('k', 'message')
    assert(verifyHmac('k', 'message', tag))
    assert(!verifyHmac('k', 'message!', tag))
    assert(!verifyHmac('k2', 'message', tag))
    assert(!verifyHmac('k', 'message', tag.slice(0, -1) + '0'))
    assert(!verifyHmac('k', 'message', null))
  })
})

describe('KDF / keystream', () => {
  it('returns exactly the requested number of bytes', () => {
    for (const n of [0, 1, 31, 32, 33, 64, 100, 1000]) equal(kdf(utf8ToBytes('secret'), 'info', n).length, n)
  })

  it('is deterministic for the same inputs', () => {
    equal(bytesToHex(kdf(utf8ToBytes('s'), 'a', 64)), bytesToHex(kdf(utf8ToBytes('s'), 'a', 64)))
  })

  it('domain separation: a different info string gives different output', () => {
    assert(bytesToHex(kdf(utf8ToBytes('s'), 'enc', 32)) !== bytesToHex(kdf(utf8ToBytes('s'), 'mac', 32)))
  })

  it('a different secret gives different output', () => {
    assert(bytesToHex(kdf(utf8ToBytes('s1'), 'i', 32)) !== bytesToHex(kdf(utf8ToBytes('s2'), 'i', 32)))
  })

  it('output extends consistently - a longer request shares its prefix', () => {
    const short = bytesToHex(kdf(utf8ToBytes('s'), 'i', 32))
    const long = bytesToHex(kdf(utf8ToBytes('s'), 'i', 96))
    assert(long.startsWith(short), 'counter-mode output must be prefix-stable')
  })

  it('keystream is the same construction under another name', () => {
    equal(bytesToHex(keystream(utf8ToBytes('k'), 'i', 40)), bytesToHex(kdf(utf8ToBytes('k'), 'i', 40)))
  })
})

describe('CBC-MAC (profile integrity)', () => {
  it('produces a 128-bit tag', () => {
    equal(cbcMacHex('key', 'profile blob').length, 32)
  })

  it('is deterministic', () => {
    equal(cbcMacHex('key', 'profile blob'), cbcMacHex('key', 'profile blob'))
  })

  it('detects a single flipped character', () => {
    assert(cbcMacHex('key', 'profile blob') !== cbcMacHex('key', 'profile bloc'))
  })

  it('depends on the key', () => {
    assert(cbcMacHex('key1', 'msg') !== cbcMacHex('key2', 'msg'))
  })

  it('resists the length-extension forgery that plain CBC-MAC allows', () => {
    // With naive zero padding these two messages would share a block sequence.
    assert(cbcMacHex('k', 'abc') !== cbcMacHex('k', 'abc '))
    assert(cbcMacHex('k', 'abc') !== cbcMacHex('k', 'abc' + ' '.repeat(13)))
  })

  it('handles empty input and inputs either side of the block size', () => {
    const tags = new Set()
    for (const n of [0, 1, 15, 16, 17, 31, 32, 33]) tags.add(cbcMacHex('k', 'a'.repeat(n)))
    equal(tags.size, 8)
  })

  it('verifyCbcMac accepts a good tag and rejects a bad one', () => {
    const tag = cbcMacHex('k', 'blob')
    assert(verifyCbcMac('k', 'blob', tag))
    assert(!verifyCbcMac('k', 'blob!', tag))
    assert(!verifyCbcMac('k', 'blob', ''))
  })
})

describe('big integer helpers', () => {
  it('modPow matches a naive reference on small inputs', () => {
    const naive = (b, e, m) => {
      let r = 1n
      for (let i = 0n; i < e; i++) r = (r * b) % m
      return r
    }
    for (const [b, e, m] of [[2n, 10n, 1000n], [7n, 13n, 97n], [123n, 45n, 6789n]]) {
      equal(modPow(b, e, m), naive(b, e, m), `${b}^${e} mod ${m}`)
    }
  })

  it('modPow handles a modulus of 1 and an exponent of 0', () => {
    equal(modPow(5n, 3n, 1n), 0n)
    equal(modPow(5n, 0n, 7n), 1n)
  })

  it('modInverse produces a genuine inverse and rejects non-invertible values', () => {
    for (const [a, m] of [[3n, 7n], [65537n, 1000003n], [17n, 3120n]]) {
      equal((a * modInverse(a, m)) % m, 1n, `inverse of ${a} mod ${m}`)
    }
    throws(() => modInverse(4n, 8n))
  })

  it('gcd is correct', () => {
    equal(gcd(12n, 18n), 6n)
    equal(gcd(17n, 5n), 1n)
  })

  it('BigInt <-> bytes round trips and enforces the target width', () => {
    const value = 0x0123456789abcdefn
    assert(timingSafeEqual(bigIntToBytes(value, 8), hexToBytes('0123456789abcdef')))
    equal(bytesToBigInt(bigIntToBytes(value, 16)), value)
    throws(() => bigIntToBytes(0x10000n, 2))
  })
})

describe('RSA - primality', () => {
  it('agrees with trial division for every integer below 2000', () => {
    const trialDivision = n => {
      if (n < 2n) return false
      for (let d = 2n; d * d <= n; d++) if (n % d === 0n) return false
      return true
    }
    for (let n = 0n; n < 2000n; n++) {
      equal(isProbablePrime(n), trialDivision(n), `disagreement at n = ${n}`)
    }
  })

  it('rejects Carmichael numbers, which fool a naive Fermat test', () => {
    for (const n of [561n, 1105n, 1729n, 2465n, 2821n, 6601n, 8911n, 10585n, 15841n]) {
      assert(!isProbablePrime(n), `${n} is composite but was accepted`)
    }
  })

  it('accepts known large primes', () => {
    for (const n of [7919n, 104729n, 1299709n, 32416190071n, (1n << 61n) - 1n]) {
      assert(isProbablePrime(n), `${n} is prime but was rejected`)
    }
  })

  it('generatePrime returns a prime of the requested width', () => {
    for (const bits of [64, 128, 256]) {
      const p = generatePrime(bits)
      equal(p.toString(2).length, bits, `${bits}-bit prime width`)
      assert(isProbablePrime(p), 'generated value is not prime')
      assert((p & 1n) === 1n, 'generated prime is even')
    }
  })
})

describe('RSA - key generation and OAEP', () => {
  // 1024 bits keeps the suite fast; a real 2048-bit key is exercised at the end.
  // Anything below 528 bits cannot carry OAEP-SHA256 at all, and the generator
  // refuses it - that boundary is asserted below.
  const key512 = generateRsaKeyPair(1024)

  it('refuses a modulus too small to carry OAEP-SHA256', () => {
    throws(() => generateRsaKeyPair(512))
    throws(() => generateRsaKeyPair(256))
  })

  it('generates a well-formed key: n = p*q and d*e = 1 mod lambda', () => {
    equal(key512.n, key512.p * key512.q, 'modulus is not the product of the primes')
    const lambda = ((key512.p - 1n) / gcd(key512.p - 1n, key512.q - 1n)) * (key512.q - 1n)
    equal((key512.d * key512.e) % lambda, 1n, 'private exponent is not the inverse of e')
    equal(key512.e, 65537n)
    assert(key512.p !== key512.q, 'p and q must differ')
  })

  it('generates a full-width modulus', () => {
    equal(key512.n.toString(2).length, 1024)
  })

  it('OAEP round trips at the boundary lengths', () => {
    const max = maxMessageLength(key512)
    for (const n of [0, 1, max - 1, max]) {
      const message = randomBytes(n)
      assert(timingSafeEqual(rsaDecrypt(key512, rsaEncrypt(key512, message)), message), `round trip at ${n} bytes`)
    }
  })

  it('OAEP refuses a message one byte over the limit', () => {
    throws(() => rsaEncrypt(key512, randomBytes(maxMessageLength(key512) + 1)))
  })

  it('OAEP is randomised - the same plaintext gives different ciphertext', () => {
    assert(bytesToHex(rsaEncrypt(key512, utf8ToBytes('x'))) !== bytesToHex(rsaEncrypt(key512, utf8ToBytes('x'))))
  })

  it('decryption with the wrong key fails rather than returning garbage', () => {
    const other = generateRsaKeyPair(1024)
    throws(() => rsaDecrypt(other, rsaEncrypt(key512, utf8ToBytes('secret'))))
  })

  it('a corrupted ciphertext is rejected', () => {
    const ct = rsaEncrypt(key512, utf8ToBytes('secret'))
    ct[10] ^= 0xff
    throws(() => rsaDecrypt(key512, ct), 'RSA_OAEP_DECODE_ERROR')
  })

  it('chunked string encryption survives a multi-byte character on a chunk boundary', () => {
    // 5000 characters is well past the 190-byte single-block limit, and the
    // trailing multilingual text guarantees a character straddles a boundary.
    const message = 'x'.repeat(5000) + 'café 漢字 🔐 naïve'
    equal(rsaDecryptString(key512, rsaEncryptString(key512, message)), message)
  })

  it('chunked string encryption handles the empty string', () => {
    equal(rsaDecryptString(key512, rsaEncryptString(key512, '')), '')
  })

  it('the fingerprint is stable and formatted for display', () => {
    const fingerprint = rsaPublicFingerprint(key512)
    equal(fingerprint, rsaPublicFingerprint(key512))
    assert(/^[0-9A-F]{4}( [0-9A-F]{4}){3}$/.test(fingerprint), `unexpected format: ${fingerprint}`)
  })

  it('generates a real RSA-2048 key with the production parameters', () => {
    const key = generateRsaKeyPair(2048)
    equal(key.n.toString(2).length, 2048)
    equal(maxMessageLength(key), 190)
    const message = 'patron@example.edu'
    equal(rsaDecryptString(key, rsaEncryptString(key, message)), message)
  })
})

describe('secp256k1 group law', () => {
  it('the generator is on the curve', () => {
    assert(isOnCurve(G))
  })

  it('rejects a point that is not on the curve', () => {
    assert(!isOnCurve({ x: G.x, y: G.y + 1n }))
    throws(() => scalarMult(2n, { x: G.x, y: G.y + 1n }), 'POINT_NOT_ON_CURVE')
  })

  it('1G = G', () => {
    const P = scalarMult(1n, G)
    equal(P.x, G.x)
    equal(P.y, G.y)
  })

  it('nG is the point at infinity', () => {
    equal(scalarMult(CURVE.n, G), null)
  })

  it('P + (-P) is the point at infinity', () => {
    equal(pointAdd(G, pointNegate(G)), null)
  })

  it('the point at infinity is the identity', () => {
    const P = pointAdd(null, G)
    equal(P.x, G.x)
    equal(pointAdd(G, null).x, G.x)
  })

  it('2G computed by doubling equals G + G', () => {
    const doubled = pointDouble(G)
    const added = pointAdd(G, G)
    equal(doubled.x, added.x)
    equal(doubled.y, added.y)
  })

  it('scalar multiplication is additive: (k1+k2)G = k1G + k2G', () => {
    for (let i = 0; i < 10; i++) {
      const k1 = randomBigIntBelow(CURVE.n - 2n) + 1n
      const k2 = randomBigIntBelow(CURVE.n - 2n) + 1n
      const lhs = scalarMult((k1 + k2) % CURVE.n, G)
      const rhs = pointAdd(scalarMult(k1, G), scalarMult(k2, G))
      equal(lhs.x, rhs.x, 'x coordinates differ')
      equal(lhs.y, rhs.y, 'y coordinates differ')
    }
  })

  it('every generated public key lies on the curve', () => {
    for (let i = 0; i < 20; i++) {
      const { priv, pub } = generateEccKeyPair()
      assert(isOnCurve(pub), 'generated public key is off the curve')
      const recomputed = publicFromPrivate(priv)
      equal(recomputed.x, pub.x)
    }
  })

  it('point compression round trips for 50 random points', () => {
    for (let i = 0; i < 50; i++) {
      const { pub } = generateEccKeyPair()
      const restored = decompressPoint(compressPoint(pub))
      equal(restored.x, pub.x, 'x lost in compression')
      equal(restored.y, pub.y, 'y lost in compression')
    }
  })

  it('compression uses the parity prefix correctly', () => {
    for (let i = 0; i < 10; i++) {
      const { pub } = generateEccKeyPair()
      const hex = compressPoint(pub)
      equal(hex.slice(0, 2), (pub.y & 1n) === 0n ? '02' : '03')
      equal(hex.length, 66)
    }
  })

  it('decompressPoint rejects malformed input', () => {
    throws(() => decompressPoint('04' + '00'.repeat(32)))
    throws(() => decompressPoint('02' + '00'.repeat(10)))
  })

  it('the ECC fingerprint is stable and formatted for display', () => {
    const { pub } = generateEccKeyPair()
    assert(/^[0-9A-F]{4}( [0-9A-F]{4}){3}$/.test(eccPublicFingerprint(pub)))
  })
})

describe('ECDH and ECIES', () => {
  const alice = generateEccKeyPair()
  const bob = generateEccKeyPair()

  it('both parties derive the same shared secret', () => {
    equal(bytesToHex(ecdh(alice.priv, bob.pub)), bytesToHex(ecdh(bob.priv, alice.pub)))
  })

  it('a third party derives a different secret', () => {
    const eve = generateEccKeyPair()
    assert(bytesToHex(ecdh(eve.priv, bob.pub)) !== bytesToHex(ecdh(alice.priv, bob.pub)))
  })

  it('ecdh rejects a public key that is not on the curve', () => {
    throws(() => ecdh(alice.priv, { x: bob.pub.x, y: bob.pub.y + 1n }), 'POINT_NOT_ON_CURVE')
  })

  it('round trips the empty string, a short record and 100 KB', () => {
    for (const message of ['', 'Borrowed: Nineteen Eighty-Four', 'x'.repeat(100_000)]) {
      equal(eciesDecryptString(alice.priv, eciesEncryptString(alice.pub, message)), message, `length ${message.length}`)
    }
  })

  it('round trips JSON records with multilingual content', () => {
    const record = JSON.stringify({ title: 'Sapiens: সংক্ষিপ্ত ইতিহাস', rating: 5, note: 'café 🔐' })
    equal(eciesDecryptString(alice.priv, eciesEncryptString(alice.pub, record)), record)
  })

  it('is non-deterministic - a fresh ephemeral key per message', () => {
    assert(eciesEncryptString(alice.pub, 'same') !== eciesEncryptString(alice.pub, 'same'))
  })

  it('rejects a flipped ciphertext byte with MAC_FAILURE', () => {
    const blob = eciesEncryptString(alice.pub, 'a private reading note')
    const index = 80
    const flipped = blob.slice(0, index) + (blob[index] === 'a' ? 'b' : 'a') + blob.slice(index + 1)
    throws(() => eciesDecryptString(alice.priv, flipped), 'MAC_FAILURE')
  })

  it('rejects a flipped authentication tag with MAC_FAILURE', () => {
    const blob = eciesEncryptString(alice.pub, 'a private reading note')
    const flipped = blob.slice(0, -1) + (blob.at(-1) === 'a' ? 'b' : 'a')
    throws(() => eciesDecryptString(alice.priv, flipped), 'MAC_FAILURE')
  })

  it('rejects decryption with the wrong private key', () => {
    throws(() => eciesDecryptString(bob.priv, eciesEncryptString(alice.pub, 'secret')))
  })

  it('rejects structurally malformed blobs', () => {
    throws(() => eciesDecryptString(alice.priv, 'not-hex!'), 'BAD_ECIES_BLOB')
    throws(() => eciesDecryptString(alice.priv, 'abcd'), 'BAD_ECIES_BLOB')
    throws(() => eciesDecryptString(alice.priv, '02' + '00'.repeat(80)), 'BAD_ECIES_BLOB')
  })

  it('ciphertext is longer than the plaintext by exactly the envelope overhead', () => {
    // version(1) + compressed ephemeral key(33) + tag(32) = 66 bytes = 132 hex chars
    const blob = eciesEncryptString(alice.pub, 'a'.repeat(100))
    equal(blob.length, (100 + 66) * 2)
  })
})

describe('TOTP (second authentication factor)', () => {
  const secret = generateTotpSecret()
  const base = 1_735_689_600_000 // a fixed instant, so the suite is reproducible

  it('generates a 160-bit base32 secret', () => {
    equal(fromBase32(secret).length, 20)
  })

  it('produces a six-digit code', () => {
    assert(/^\d{6}$/.test(totpCode(secret, base)))
  })

  it('is stable throughout a 30-second step', () => {
    equal(totpCode(secret, base), totpCode(secret, base + 29_999))
  })

  it('changes on the next step', () => {
    assert(totpCode(secret, base) !== totpCode(secret, base + 30_000))
  })

  it('accepts the previous, current and next step', () => {
    for (const offset of [-30_000, 0, 30_000]) {
      assert(verifyTotp(secret, totpCode(secret, base + offset), base), `offset ${offset} rejected`)
    }
  })

  it('rejects a code from five steps away', () => {
    assert(!verifyTotp(secret, totpCode(secret, base + 150_000), base))
    assert(!verifyTotp(secret, totpCode(secret, base - 150_000), base))
  })

  it('rejects malformed codes', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', null, undefined, '12 45 6']) {
      assert(!verifyTotp(secret, bad, base), `accepted ${JSON.stringify(bad)}`)
    }
  })

  it('different secrets give different codes', () => {
    assert(totpCode(secret, base) !== totpCode(generateTotpSecret(), base))
  })

  it('secondsRemaining stays within the step', () => {
    const remaining = secondsRemaining(base + 7000)
    assert(remaining > 0 && remaining <= 30, `got ${remaining}`)
  })

  it('the otpauth URI carries the parameters an authenticator needs', () => {
    const uri = totpUri(secret, 'patron.one')
    assert(uri.startsWith('otpauth://totp/BookVault%3Apatron.one?'), uri)
    assert(uri.includes(`secret=${secret}`))
    assert(uri.includes('algorithm=SHA256'))
    assert(uri.includes('digits=6'))
    assert(uri.includes('period=30'))
  })
})

describe('private-key wrapping', () => {
  const salt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
  const key = deriveWrapKey('Correct-Horse-9!', salt, 1000)

  it('derivation is deterministic for the same password and salt', () => {
    equal(bytesToHex(deriveWrapKey('Correct-Horse-9!', salt, 1000)), bytesToHex(key))
  })

  it('a different password gives a different key', () => {
    assert(bytesToHex(deriveWrapKey('Correct-Horse-9', salt, 1000)) !== bytesToHex(key))
  })

  it('a different salt gives a different key', () => {
    assert(bytesToHex(deriveWrapKey('Correct-Horse-9!', 'f'.repeat(32), 1000)) !== bytesToHex(key))
  })

  it('the iteration count changes the result', () => {
    assert(bytesToHex(deriveWrapKey('Correct-Horse-9!', salt, 999)) !== bytesToHex(key))
  })

  it('round trips wrapped material', () => {
    for (const secret of ['', 'd=0x1234', 'x'.repeat(5000)]) {
      equal(unwrapString(key, wrapString(key, secret)), secret, `length ${secret.length}`)
    }
  })

  it('is non-deterministic - a fresh nonce per wrap', () => {
    assert(wrapString(key, 'same') !== wrapString(key, 'same'))
  })

  it('the wrong password fails loudly instead of returning garbage', () => {
    const wrong = deriveWrapKey('wrong-password', salt, 1000)
    throws(() => unwrapString(wrong, wrapString(key, 'private-exponent')), 'WRAP_MAC_FAILURE')
  })

  it('a flipped ciphertext byte is rejected', () => {
    const blob = wrapString(key, 'private-exponent')
    const index = 40
    const flipped = blob.slice(0, index) + (blob[index] === 'a' ? 'b' : 'a') + blob.slice(index + 1)
    throws(() => unwrapString(key, flipped), 'WRAP_MAC_FAILURE')
  })

  it('malformed blobs are rejected', () => {
    for (const bad of ['', 'zz', 'abc', '00'.repeat(10)]) {
      throws(() => unwrapString(key, bad), 'WRAP_MAC_FAILURE')
    }
  })
})

describe('password hashing', () => {
  it('the same password and salt always hash the same way', () => {
    const { salt, hash } = hashPassword('Correct-Horse-9!')
    equal(hashPasswordWithSalt('Correct-Horse-9!', salt), hash)
  })

  it('a fresh salt is used for every registration', () => {
    const a = hashPassword('same-password')
    const b = hashPassword('same-password')
    assert(a.salt !== b.salt, 'salts repeated')
    assert(a.hash !== b.hash, 'identical passwords produced identical hashes')
  })

  it('the salt is 128 bits', () => {
    equal(hashPassword('x').salt.length, 32)
  })

  it('verifyPassword accepts the right password and rejects everything else', () => {
    const { salt, hash } = hashPassword('Correct-Horse-9!')
    assert(verifyPassword('Correct-Horse-9!', salt, hash))
    assert(!verifyPassword('correct-horse-9!', salt, hash), 'case-insensitive match')
    assert(!verifyPassword('Correct-Horse-9', salt, hash))
    assert(!verifyPassword('', salt, hash))
    assert(!verifyPassword('Correct-Horse-9!', 'f'.repeat(32), hash), 'wrong salt accepted')
  })

  it('verifyPassword tolerates missing stored values', () => {
    assert(!verifyPassword('x', null, null))
    assert(!verifyPassword('x', undefined, undefined))
  })
})

describe('dependency hygiene', () => {
  it('no file under server/src imports a built-in or third-party crypto library', () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
    const forbidden = [
      /from\s+['"]node:crypto['"]/,
      /from\s+['"]crypto['"]/,
      /require\(\s*['"](node:)?crypto['"]\s*\)/,
      /from\s+['"]bcrypt(js)?['"]/,
      /from\s+['"]jose['"]/,
      /from\s+['"]crypto-js['"]/,
      /from\s+['"]elliptic['"]/,
      /from\s+['"]node-forge['"]/,
      /from\s+['"]tweetnacl['"]/,
      /from\s+['"]@noble\//,
    ]

    const offenders = []
    const walk = dir => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry)
        if (statSync(full).isDirectory()) walk(full)
        else if (entry.endsWith('.js')) {
          const source = readFileSync(full, 'utf8')
          for (const pattern of forbidden) {
            if (pattern.test(source)) offenders.push(`${relative(root, full)} matches ${pattern}`)
          }
        }
      }
    }
    walk(root)
    assert(offenders.length === 0, `forbidden crypto imports found:\n       ${offenders.join('\n       ')}`)
  })

  it('getRandomValues is called in exactly one file', () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
    // Comments are stripped first - several files legitimately *mention*
    // getRandomValues while explaining where entropy comes from.
    const stripComments = source => source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
    const users = []
    const walk = dir => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry)
        if (statSync(full).isDirectory()) walk(full)
        else if (entry.endsWith('.js') && /getRandomValues\s*\(/.test(stripComments(readFileSync(full, 'utf8')))) {
          users.push(relative(root, full).replace(/\\/g, '/'))
        }
      }
    }
    walk(root)
    equal(users.join(','), 'crypto/random.js', `unexpected entropy sources: ${users.join(', ')}`)
  })

  it('the declared dependencies contain no crypto package', () => {
    const pkg = JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'),
    )
    const names = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })
    const suspicious = names.filter(n => /crypto|bcrypt|jose|forge|elliptic|noble|nacl|jsonwebtoken/i.test(n))
    assert(suspicious.length === 0, `suspicious dependencies: ${suspicious.join(', ')}`)
  })
})

// ---------------------------------------------------------------------------
console.log(`\n\x1b[1mTotal\x1b[0m  ${passed} passed, ${failed} failed`)
if (failed) {
  console.log('\nFailures:')
  for (const f of failures) console.log('  - ' + f)
  process.exit(1)
}
console.log(green('\nAll cryptographic tests passed.\n'))
