/**
 * Byte / encoding helpers.
 *
 * Everything in the crypto layer speaks Uint8Array in memory and lowercase hex
 * at rest. Node Buffers are deliberately avoided so the same code would run
 * unchanged in a browser or any other JS runtime.
 */

const HEX = '0123456789abcdef'
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' // RFC 4648

/** UTF-8 encode without TextEncoder, so the byte layout is explicit. */
export function utf8ToBytes(str) {
  if (str instanceof Uint8Array) return str
  if (typeof str !== 'string') throw new TypeError('utf8ToBytes expects a string')
  const out = []
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i)
    // Combine surrogate pairs into a single code point.
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1)
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = (code - 0xd800) * 0x400 + (next - 0xdc00) + 0x10000
        i++
      }
    }
    if (code < 0x80) {
      out.push(code)
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f))
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f))
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      )
    }
  }
  return Uint8Array.from(out)
}

export function bytesToUtf8(bytes) {
  if (typeof bytes === 'string') return bytes
  let out = ''
  for (let i = 0; i < bytes.length; ) {
    const b0 = bytes[i]
    let code
    let size
    if (b0 < 0x80) {
      code = b0
      size = 1
    } else if ((b0 & 0xe0) === 0xc0) {
      code = b0 & 0x1f
      size = 2
    } else if ((b0 & 0xf0) === 0xe0) {
      code = b0 & 0x0f
      size = 3
    } else if ((b0 & 0xf8) === 0xf0) {
      code = b0 & 0x07
      size = 4
    } else {
      // Invalid lead byte - emit the replacement character and resynchronise.
      out += '�'
      i++
      continue
    }
    if (i + size > bytes.length) {
      out += '�'
      break
    }
    for (let k = 1; k < size; k++) code = (code << 6) | (bytes[i + k] & 0x3f)
    i += size
    if (code > 0xffff) {
      code -= 0x10000
      out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff))
    } else {
      out += String.fromCharCode(code)
    }
  }
  return out
}

export function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0f]
  }
  return out
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new TypeError('hexToBytes expects a string')
  if (hex.length % 2 !== 0) throw new Error('hexToBytes: odd-length input')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.substr(i * 2, 2), 16)
    if (Number.isNaN(byte)) throw new Error('hexToBytes: non-hex character')
    out[i] = byte
  }
  return out
}

export function concatBytes(...arrays) {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    out.set(a, offset)
    offset += a.length
  }
  return out
}

export function xorBytes(a, b) {
  const len = Math.min(a.length, b.length)
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i]
  return out
}

/**
 * Constant-time equality. The length is compared first (lengths are not secret
 * in any of our uses), then every byte is folded into a single accumulator so
 * the running time does not depend on where the first difference occurs.
 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** RFC 4648 base32, uppercase, no padding - the encoding authenticator apps expect. */
export function toBase32(bytes) {
  let bits = 0
  let value = 0
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]
    bits += 8
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export function fromBase32(str) {
  const clean = String(str).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')
  let bits = 0
  let value = 0
  const out = []
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch)
    if (idx === -1) throw new Error('fromBase32: invalid character')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Uint8Array.from(out)
}
