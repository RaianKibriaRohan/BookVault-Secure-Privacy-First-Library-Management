/**
 * Counter-mode key derivation over SHA-256 (the shape of NIST SP 800-108 KDF
 * in counter mode, built from our own hash):
 *
 *   T_i = SHA256( be32(i) || secret || utf8(info) )      i = 1, 2, 3, ...
 *   out = (T_1 || T_2 || ...) truncated to lengthBytes
 *
 * The `info` string is a domain separator: the same shared secret produces
 * completely unrelated keys for ECIES encryption, ECIES authentication and key
 * wrapping, so a value derived for one purpose is useless for another.
 */
import { sha256 } from './sha256.js'
import { utf8ToBytes, concatBytes } from './bytes.js'

export function kdf(secretBytes, info, lengthBytes) {
  if (!Number.isInteger(lengthBytes) || lengthBytes < 0) {
    throw new RangeError('kdf: bad length')
  }
  const secret = typeof secretBytes === 'string' ? utf8ToBytes(secretBytes) : secretBytes
  const infoBytes = utf8ToBytes(info ?? '')
  const out = new Uint8Array(lengthBytes)
  const counter = new Uint8Array(4)
  let offset = 0
  let i = 1
  while (offset < lengthBytes) {
    counter[0] = (i >>> 24) & 0xff
    counter[1] = (i >>> 16) & 0xff
    counter[2] = (i >>> 8) & 0xff
    counter[3] = i & 0xff
    const block = sha256(concatBytes(counter, secret, infoBytes))
    const take = Math.min(32, lengthBytes - offset)
    out.set(block.subarray(0, take), offset)
    offset += take
    i++
  }
  return out
}

/**
 * The same construction used as a stream generator. ECIES and the key-wrap
 * routine XOR this keystream into their payloads; because every invocation uses
 * a fresh ephemeral secret (ECIES) or a fresh nonce (key wrap), no keystream is
 * ever reused - which is the property a stream construction lives or dies by.
 */
export function keystream(keyBytes, info, lengthBytes) {
  return kdf(keyBytes, info, lengthBytes)
}
