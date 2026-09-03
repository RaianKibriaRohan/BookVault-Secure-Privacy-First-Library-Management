import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, type ChatMessage, type ChatThread } from '../lib/api'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  InfoNote,
  IntegrityBadge,
  KeysLocked,
  LockIcon,
  PageHeader,
  Spinner,
  Textarea,
  useToast,
} from '../components/ui'
import { useReSignIn } from '../context/AuthContext'
import { cx, fmtDate, fmtTime, relativeTime } from '../lib/format'

const MAX_BODY = 4000
const POLL_MS = 8000

/**
 * The messenger surface, shared by the patron and librarian sides. The only
 * difference between them is the thread list: a patron has exactly one
 * correspondent, the librarian has as many as have written in.
 */
export function ChatSurface({ title, subtitle }: { title: string; subtitle: string }) {
  const toast = useToast()
  const reSignIn = useReSignIn()

  const [locked, setLocked] = useState(false)
  const [threads, setThreads] = useState<ChatThread[]>([])
  const [activePeer, setActivePeer] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [draft, setDraft] = useState('')
  const [loadingThreads, setLoadingThreads] = useState(true)
  const [loadingMessages, setLoadingMessages] = useState(false)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const endRef = useRef<HTMLDivElement | null>(null)

  const loadThreads = useCallback(async () => {
    try {
      const data = await api.chat.threads()
      setThreads(data.threads)
      setActivePeer(current => current ?? data.threads[0]?.peerId ?? null)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load conversations.')
    } finally {
      setLoadingThreads(false)
    }
  }, [])

  const loadMessages = useCallback(async (peerId: string, showSpinner = false) => {
    if (showSpinner) setLoadingMessages(true)
    try {
      const data = await api.chat.messages(peerId)
      setMessages(data.messages)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'KEYS_LOCKED') setLocked(true)
      else setError(err instanceof ApiError ? err.message : 'Could not load messages.')
    } finally {
      setLoadingMessages(false)
    }
  }, [])

  useEffect(() => {
    void loadThreads()
  }, [loadThreads])

  useEffect(() => {
    if (!activePeer) return
    void loadMessages(activePeer, true)
  }, [activePeer, loadMessages])

  // Light polling while the page is mounted; cleaned up on unmount.
  useEffect(() => {
    if (!activePeer) return
    const timer = setInterval(() => {
      void loadMessages(activePeer)
      void loadThreads()
    }, POLL_MS)
    return () => clearInterval(timer)
  }, [activePeer, loadMessages, loadThreads])

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [messages.length])

  const send = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!activePeer || !draft.trim()) return
    setSending(true)
    try {
      await api.chat.send(activePeer, draft.trim())
      setDraft('')
      await loadMessages(activePeer)
      await loadThreads()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not send the message.', 'error')
    } finally {
      setSending(false)
    }
  }

  const activeThread = threads.find(t => t.peerId === activePeer)

  if (locked) return <KeysLocked onSignOut={reSignIn} />

  if (loadingThreads) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  return (
    <>
      <PageHeader title={title} subtitle={subtitle} />

      {error && <ErrorNote className="mb-4">{error}</ErrorNote>}

      {threads.length === 0 ? (
        <EmptyState title="No conversations yet" hint="Messages sent to you will appear here." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
          {/* Thread list */}
          <Card className="h-fit overflow-hidden">
            <div className="border-b border-line px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-faint">
              Conversations
            </div>
            <div className="max-h-[26rem] overflow-y-auto">
              {threads.map(thread => (
                <button
                  key={thread.peerId}
                  onClick={() => setActivePeer(thread.peerId)}
                  className={cx(
                    'flex w-full items-center gap-3 border-b border-line-soft px-3 py-2.5 text-left transition-colors last:border-0',
                    thread.peerId === activePeer ? 'bg-accent/8' : 'hover:bg-surface-2',
                  )}
                >
                  <div
                    className={cx(
                      'mono flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs',
                      thread.peerRole === 'admin' ? 'bg-violet/15 text-violet' : 'bg-accent-2/15 text-accent-2',
                    )}
                  >
                    {thread.peerName.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-slate-200">{thread.peerName}</div>
                    <div className="text-[11px] text-faint">
                      {thread.lastMessageAt ? relativeTime(thread.lastMessageAt) : 'no messages yet'}
                    </div>
                  </div>
                  {thread.unread > 0 && <Badge tone="accent">{thread.unread}</Badge>}
                </button>
              ))}
            </div>
          </Card>

          {/* Messages */}
          <Card className="flex min-h-[28rem] flex-col">
            <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-200">{activeThread?.peerName ?? '—'}</span>
                {activeThread?.peerRole === 'admin' && <Badge tone="violet">Head Librarian</Badge>}
                {activeThread?.peerStatus === 'suspended' && <Badge tone="danger">Suspended</Badge>}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] text-faint">
                <LockIcon size={11} /> RSA-2048 · HMAC over an ECDH secret
              </div>
            </div>

            <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4" style={{ maxHeight: '26rem' }}>
              {loadingMessages ? (
                <div className="flex justify-center py-10 text-muted">
                  <Spinner size={18} />
                </div>
              ) : messages.length === 0 ? (
                <div className="py-10 text-center text-sm text-faint">
                  No messages yet. Ask about a book request, a damaged copy, or your account.
                </div>
              ) : (
                messages.map((message, index) => {
                  const previous = messages[index - 1]
                  const newDay =
                    !previous || fmtDate(previous.ts) !== fmtDate(message.ts)
                  return (
                    <div key={message.id}>
                      {newDay && (
                        <div className="my-3 flex items-center gap-3">
                          <div className="h-px flex-1 bg-line-soft" />
                          <span className="text-[10px] uppercase tracking-wider text-faint">{fmtDate(message.ts)}</span>
                          <div className="h-px flex-1 bg-line-soft" />
                        </div>
                      )}
                      <div className={cx('flex', message.direction === 'out' ? 'justify-end' : 'justify-start')}>
                        <div
                          className={cx(
                            'max-w-[85%] rounded-xl2 border px-3.5 py-2.5 sm:max-w-[70%]',
                            message.integrity !== 'ok'
                              ? 'border-danger/40 bg-danger/8'
                              : message.direction === 'out'
                                ? 'border-accent/25 bg-accent/10'
                                : 'border-line bg-surface-2',
                          )}
                        >
                          {message.integrity === 'ok' ? (
                            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100">{message.body}</p>
                          ) : (
                            <p className="text-sm text-danger">
                              {message.integrity === 'tampered'
                                ? 'This message failed its authentication tag and was not decrypted.'
                                : 'This message cannot be decrypted with your current keys.'}
                            </p>
                          )}
                          <div className="mt-1.5 flex items-center gap-2 text-[10px] text-faint">
                            <span>{fmtTime(message.ts)}</span>
                            {message.integrity !== 'ok' && <IntegrityBadge integrity={message.integrity} />}
                            {message.direction === 'out' && message.integrity === 'ok' && (
                              <span>{message.read ? 'read' : 'sent'}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })
              )}
              <div ref={endRef} />
            </div>

            <form onSubmit={send} className="border-t border-line p-3">
              <Textarea
                rows={2}
                maxLength={MAX_BODY}
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) void send(e as unknown as React.FormEvent)
                }}
                placeholder="Write a message…"
                disabled={!activePeer}
              />
              <div className="mt-2 flex items-center justify-between">
                <span className="text-[11px] text-faint">
                  {draft.length} / {MAX_BODY} · Ctrl+Enter to send
                </span>
                <Button type="submit" size="sm" loading={sending} disabled={!draft.trim() || !activePeer}>
                  Encrypt and send
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      <InfoNote className="mt-5">
        Each message is encrypted with the recipient&apos;s RSA-2048 public key, plus a second copy under your own so your
        outbox still renders. The authentication tag is an HMAC-SHA256 keyed by an ECDH shared secret, computed over the
        ciphertext <em>and</em> the timestamp — which is what makes a captured message impossible to replay.
      </InfoNote>
    </>
  )
}

export default function Chat() {
  return (
    <ChatSurface
      title="Secure chat"
      subtitle="Request a book, report a damaged copy, or ask about your account. The server stores only ciphertext — it cannot read these messages either."
    />
  )
}
