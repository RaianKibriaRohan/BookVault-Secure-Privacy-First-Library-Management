/**
 * Secure patron <-> librarian chat (feature F8 for patrons, A4 for the admin).
 *
 * Confidentiality : the body is RSA-OAEP encrypted under the recipient's public
 *                   key. A second copy is encrypted under the sender's own
 *                   public key so their outbox still renders - RSA encrypts to
 *                   exactly one recipient, so without that copy a sender could
 *                   never re-read what they sent. Both copies are opaque to the
 *                   server and to everyone else.
 * Authenticity    : an HMAC-SHA256 tag computed with a key derived by ECDH
 *                   between sender and recipient. Only those two parties can
 *                   compute or verify it, so the tag proves authorship.
 * Replay/tamper   : the message timestamp is bound into the MAC input, so a
 *                   captured ciphertext cannot be re-inserted under a new time
 *                   without invalidating the tag.
 */
import { Router } from 'express'
import { db, unwrap } from '../db/supabase.js'
import { asyncHandler, httpError } from '../middleware/errors.js'
import { requireAuth, requireKeys } from '../middleware/auth.js'
import { rsaEncryptString, rsaDecryptString } from '../crypto/rsa.js'
import { hmacSha256Hex, verifyHmac } from '../crypto/hmac.js'
import { ecdh } from '../crypto/ecc.js'
import { loadPublicKeys } from '../services/keyManagement.js'
import { DOMAINS } from '../services/records.js'
import { audit } from '../services/audit.js'

const router = Router()

const MAX_BODY = 4000

const macInput = (ciphertext, ts) => DOMAINS.chat + ciphertext + ts

router.get(
  '/threads',
  requireAuth,
  asyncHandler(async (req, res) => {
    if (req.user.role === 'patron') {
      // A patron only ever talks to the librarians.
      const admins = unwrap(
        await db.from('users').select('id, username, role, status').eq('role', 'admin').order('username'),
        'librarian list',
      )
      const threads = []
      for (const admin of admins) {
        const last = unwrap(
          await db
            .from('chat_messages')
            .select('ts, sender_id')
            .or(`and(sender_id.eq.${req.user.id},recipient_id.eq.${admin.id}),and(sender_id.eq.${admin.id},recipient_id.eq.${req.user.id})`)
            .order('ts', { ascending: false })
            .limit(1)
            .maybeSingle(),
          'thread peek',
        )
        const unread = unwrap(
          await db
            .from('chat_messages')
            .select('id', { count: 'exact', head: true })
            .eq('sender_id', admin.id)
            .eq('recipient_id', req.user.id)
            .is('read_at', null),
          'unread count',
        )
        threads.push({
          peerId: admin.id,
          peerName: admin.username,
          peerRole: 'admin',
          lastMessageAt: last?.ts ?? null,
          unread: unread?.length ?? 0,
        })
      }
      return res.json({ threads })
    }

    // Admin view: every patron who has ever exchanged a message.
    const rows = unwrap(
      await db
        .from('chat_messages')
        .select('sender_id, recipient_id, ts, read_at')
        .or(`sender_id.eq.${req.user.id},recipient_id.eq.${req.user.id}`)
        .order('ts', { ascending: false }),
      'thread list',
    )
    const byPeer = new Map()
    for (const row of rows) {
      const peerId = row.sender_id === req.user.id ? row.recipient_id : row.sender_id
      const entry = byPeer.get(peerId) ?? { peerId, lastMessageAt: row.ts, unread: 0 }
      entry.lastMessageAt = Math.max(entry.lastMessageAt, row.ts)
      if (row.recipient_id === req.user.id && !row.read_at) entry.unread++
      byPeer.set(peerId, entry)
    }
    if (byPeer.size === 0) return res.json({ threads: [] })

    const users = unwrap(
      await db.from('users').select('id, username, role, status').in('id', [...byPeer.keys()]),
      'peer lookup',
    )
    const nameOf = new Map(users.map(u => [u.id, u]))
    const threads = [...byPeer.values()]
      .map(t => ({
        ...t,
        peerName: nameOf.get(t.peerId)?.username ?? 'unknown',
        peerRole: nameOf.get(t.peerId)?.role ?? 'patron',
        peerStatus: nameOf.get(t.peerId)?.status ?? 'active',
      }))
      .sort((a, b) => b.lastMessageAt - a.lastMessageAt)

    res.json({ threads })
  }),
)

router.get(
  '/messages',
  requireAuth,
  requireKeys,
  asyncHandler(async (req, res) => {
    const peerId = String(req.query.peerId ?? '')
    if (!peerId) throw httpError(400, 'VALIDATION_ERROR', 'A peerId is required.')

    const peer = unwrap(await db.from('users').select('id, username, role').eq('id', peerId).maybeSingle(), 'peer lookup')
    if (!peer) throw httpError(404, 'NOT_FOUND', 'No such user.')
    if (req.user.role === 'patron' && peer.role !== 'admin') {
      throw httpError(403, 'FORBIDDEN', 'Patrons can only message the librarian.')
    }

    const rows = unwrap(
      await db
        .from('chat_messages')
        .select('*')
        .or(`and(sender_id.eq.${req.user.id},recipient_id.eq.${peerId}),and(sender_id.eq.${peerId},recipient_id.eq.${req.user.id})`)
        .order('ts', { ascending: true }),
      'message list',
    )

    const peerKeys = await loadPublicKeys(peerId)
    const shared = ecdh(req.keys.ecc.priv, peerKeys.ecc)

    const messages = []
    const toMarkRead = []

    for (const row of rows) {
      const outbound = row.sender_id === req.user.id
      const blob = outbound ? row.body_for_sender : row.body_for_recipient

      // The tag always covers the recipient's copy, so both parties verify the
      // same bytes and reach the same verdict.
      const authentic = verifyHmac(shared, macInput(row.body_for_recipient, row.ts), row.hmac_tag)

      let body = null
      let integrity = 'ok'
      if (!authentic) {
        integrity = 'tampered'
      } else {
        try {
          body = rsaDecryptString(req.keys.rsa, blob)
        } catch {
          // Most often a message sealed under a key version that has since been
          // rotated away - authentic, but no longer readable.
          integrity = 'undecryptable'
        }
      }

      if (!outbound && !row.read_at) toMarkRead.push(row.id)

      messages.push({
        id: row.id,
        direction: outbound ? 'out' : 'in',
        body,
        ts: Number(row.ts),
        integrity,
        read: outbound ? Boolean(row.read_at) : true,
        keyVersion: outbound ? row.sender_key_version : row.recipient_key_version,
        raw: { ciphertext: row.body_for_recipient, hmacTag: row.hmac_tag },
      })
    }

    if (toMarkRead.length) {
      await db.from('chat_messages').update({ read_at: new Date().toISOString() }).in('id', toMarkRead)
    }

    res.json({ messages, peer: { id: peer.id, username: peer.username, role: peer.role } })
  }),
)

router.post(
  '/messages',
  requireAuth,
  requireKeys,
  asyncHandler(async (req, res) => {
    const peerId = String(req.body?.peerId ?? '')
    const body = String(req.body?.body ?? '').trim()

    if (!peerId) throw httpError(400, 'VALIDATION_ERROR', 'A peerId is required.')
    if (!body) throw httpError(400, 'VALIDATION_ERROR', 'Write a message first.')
    if (body.length > MAX_BODY) throw httpError(400, 'VALIDATION_ERROR', `Messages are limited to ${MAX_BODY} characters.`)
    if (peerId === req.user.id) throw httpError(400, 'VALIDATION_ERROR', 'You cannot message yourself.')

    const peer = unwrap(await db.from('users').select('id, username, role, status').eq('id', peerId).maybeSingle(), 'peer lookup')
    if (!peer) throw httpError(404, 'NOT_FOUND', 'No such user.')
    if (req.user.role === 'patron' && peer.role !== 'admin') {
      throw httpError(403, 'FORBIDDEN', 'Patrons can only message the librarian.')
    }

    const peerKeys = await loadPublicKeys(peerId)

    const forRecipient = rsaEncryptString(peerKeys.rsa, body)
    const forSender = rsaEncryptString(req.keys.rsa, body)
    const ts = Date.now()

    const shared = ecdh(req.keys.ecc.priv, peerKeys.ecc)
    const tag = hmacSha256Hex(shared, macInput(forRecipient, ts))

    const row = unwrap(
      await db
        .from('chat_messages')
        .insert({
          sender_id: req.user.id,
          recipient_id: peerId,
          body_for_recipient: forRecipient,
          body_for_sender: forSender,
          hmac_tag: tag,
          ts,
          sender_key_version: req.keys.keyVersion,
          recipient_key_version: peerKeys.version,
        })
        .select()
        .single(),
      'message insert',
    )

    await audit(req, {
      userId: req.user.id,
      username: req.user.username,
      eventType: 'chat_send',
      detail: `to ${peer.username}: RSA-encrypted, HMAC over ECDH shared secret`,
    })

    res.status(201).json({
      message: { id: row.id, direction: 'out', body, ts, integrity: 'ok', read: false, keyVersion: req.keys.keyVersion },
    })
  }),
)

export default router
