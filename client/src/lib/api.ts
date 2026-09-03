/**
 * Typed client for the BookVault API.
 *
 * Every request carries the session cookie (credentials: 'include'); the token
 * itself is HttpOnly and never visible to this code, which is the point.
 */

export type Integrity = 'ok' | 'tampered' | 'undecryptable'
export type Role = 'patron' | 'admin'

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method,
      credentials: 'include',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Could not reach the BookVault API. Is the server running?')
  }

  const text = await res.text()
  let data: any = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = { raw: text }
    }
  }

  if (!res.ok) {
    throw new ApiError(res.status, data?.error?.code ?? 'UNKNOWN', data?.error?.message ?? `Request failed (${res.status}).`)
  }
  return data as T
}

const get = <T,>(path: string) => request<T>('GET', path)
const post = <T,>(path: string, body?: unknown) => request<T>('POST', path, body ?? {})
const put = <T,>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {})
const patch = <T,>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {})
const del = <T,>(path: string) => request<T>('DELETE', path)

const qs = (params: Record<string, string | undefined>) => {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value) search.set(key, value)
  const s = search.toString()
  return s ? `?${s}` : ''
}

// --- Types -----------------------------------------------------------------

export interface User {
  id: string
  username: string
  role: Role
  status: 'active' | 'suspended'
  keyVersion: number
  createdAt: string
  lastLoginAt: string | null
}

export interface SessionInfo {
  expiresAt: string
  lastActiveAt?: string
  idleTimeoutMinutes: number
  ipFingerprint?: string
}

export interface MeResponse {
  user: User
  session: SessionInfo
  keysUnlocked: boolean
  labRoutes: boolean
}

export interface Fingerprints {
  rsa: string
  ecc: string
  rsaBits: number
  curve: string
}

export interface RegisterResponse {
  ok: true
  userId: string
  username: string
  totpSecret: string
  totpUri: string
  fingerprints: Fingerprints
}

export interface LoginChallenge {
  stage: '2fa'
  challengeId: string
  expiresIn: number
  digits: number
}

export interface Book {
  id: string
  title: string
  author: string
  isbn: string
  genre: string
  description: string
  publishedYear: number | null
  totalCopies: number
  availableCopies: number
  coverHue: number
  createdAt: string
}

export interface BookInput {
  title: string
  author: string
  isbn: string
  genre: string
  description?: string
  publishedYear?: number | string | null
  totalCopies?: number | string
  coverHue?: number | string
}

export interface FineBreakdownRow {
  tier: string
  days: number
  rate: number
  subtotal: number
}

export interface FineComputation {
  amount: number
  daysOverdue: number
  replacementNotice: boolean
  currency: string
  breakdown: FineBreakdownRow[]
}

export interface CheckoutItem {
  id: string
  book: { id: string; title: string; author: string; isbn: string } | null
  checkoutDate: string
  dueDate: string
  status: 'active' | 'returned'
  returnedAt: string | null
  daysLeft: number
  overdueDays: number
  projectedFine: FineComputation | null
  keyVersion: number
  integrity: Integrity
  raw: { ciphertext: string; hmacTag: string }
}

export interface FineItem {
  id: string
  amount: number
  daysOverdue: number
  status: 'unpaid' | 'paid'
  replacementNotice: boolean
  createdAt: string
  paidAt: string | null
  keyVersion: number
  integrity: Integrity
  detail: {
    title: string
    author: string
    dueDate: string
    returnedAt: string
    breakdown: FineBreakdownRow[]
  } | null
  raw: { ciphertext: string; hmacTag: string }
}

export interface FineSummary {
  outstanding: number
  paid: number
  total: number
  unpaidCount: number
  blocked: boolean
  currency: string
}

export interface ReviewItem {
  id: string
  bookId: string | null
  bookTitle: string | null
  author: string | null
  rating: number | null
  body: string | null
  writtenAt: string
  createdAt: string
  updatedAt: string
  keyVersion: number
  integrity: Integrity
  raw: { ciphertext: string; hmacTag: string }
}

export interface EligibleBook {
  id: string
  title: string
  author: string
  returnedAt: string
}

export interface ChatThread {
  peerId: string
  peerName: string
  peerRole: Role
  peerStatus?: string
  lastMessageAt: number | null
  unread: number
}

export interface ChatMessage {
  id: string
  direction: 'in' | 'out'
  body: string | null
  ts: number
  integrity: Integrity
  read: boolean
  keyVersion: number
  raw?: { ciphertext: string; hmacTag: string }
}

export interface ProfileFields {
  email: string | null
  phone: string | null
  libraryCard: string | null
  fullName: string | null
  address: string | null
}

export interface ProfileResponse {
  fields: ProfileFields
  macValid: boolean
  decryptable: boolean
  keyVersion: number
  updatedAt: string
  ciphertext: Record<keyof ProfileFields, string>
  profileMac: string
}

export interface KeyInfo {
  version: number
  createdAt: string
  rsa: { fingerprint: string; modulusBits: number; publicExponent: string; algorithm: string; usedFor: string }
  ecc: { fingerprint: string; curve: string; algorithm: string; usedFor: string }
  mac: { algorithm: string }
  history: { version: number; created_at: string; retired_at: string | null }[]
  sessions: {
    id: string
    createdAt: string
    lastActiveAt: string
    expiresAt: string
    revoked: boolean
    reason: string | null
    current: boolean
  }[]
}

export interface RotationCategory {
  rekeyed: number
  tampered: number
}

export interface RotationResponse {
  ok: true
  version: number
  fingerprints: Fingerprints
  steps: string[]
  report: {
    from: number
    to: number
    checkouts: RotationCategory
    fines: RotationCategory
    reviews: RotationCategory
    chat: RotationCategory
    profile: RotationCategory
  }
}

export interface AdminStats {
  patrons: number
  admins: number
  suspended: number
  titles: number
  copies: number
  copiesOnLoan: number
  activeCheckouts: number
  overdueCheckouts: number
  outstandingFines: number
  paidFines: number
  unreadMessages: number
  events24h: number
  failures24h: number
  warnings24h: number
}

export interface AdminUser {
  id: string
  username: string
  role: Role
  status: 'active' | 'suspended'
  keyVersion: number
  createdAt: string
  lastLoginAt: string | null
  failedLogins: number
  checkouts: number
  activeCheckouts: number
  outstandingFines: number
}

export interface AdminFine {
  id: string
  userId: string
  username: string
  userStatus: string
  amount: number
  daysOverdue: number
  status: 'unpaid' | 'paid'
  replacementNotice: boolean
  createdAt: string
  paidAt: string | null
  ciphertext: string
  hmacTag: string
}

export interface AuditEntry {
  id: string
  userId: string | null
  username: string | null
  eventType: string
  outcome: 'success' | 'failure' | 'warning'
  detail: string
  ip: string | null
  createdAt: string
}

export type EncryptedTable = 'checkouts' | 'reviews' | 'fines' | 'chat_messages'

export interface EncryptedRow {
  id: string
  username?: string | null
  recipientName?: string | null
  ciphertext?: string
  body_for_recipient?: string
  hmac_tag: string
  key_version?: number
  created_at: string
  [key: string]: unknown
}

export interface SelfTestResult {
  name: string
  expected: string
  actual: string
  pass: boolean
  ms: number
}

// --- API surface -----------------------------------------------------------

export const api = {
  auth: {
    register: (payload: {
      username: string
      password: string
      email: string
      phone: string
      libraryCard: string
      fullName: string
      address: string
    }) => post<RegisterResponse>('/api/auth/register', payload),
    login: (username: string, password: string) => post<LoginChallenge>('/api/auth/login', { username, password }),
    verify2fa: (challengeId: string, code: string) =>
      post<{ user: User; session: SessionInfo }>('/api/auth/verify-2fa', { challengeId, code }),
    logout: () => post<{ ok: true }>('/api/auth/logout'),
    me: () => get<MeResponse>('/api/auth/me'),
    challengeCode: (challengeId: string) =>
      post<{ code: string; secondsRemaining: number }>('/api/auth/challenge-code', { challengeId }),
  },

  books: {
    list: (params: { q?: string; genre?: string; availability?: string } = {}) =>
      get<{ books: Book[]; count: number }>(`/api/books${qs(params)}`),
    genres: () => get<{ genres: { genre: string; count: number }[] }>('/api/books/genres'),
    get: (id: string) => get<{ book: Book }>(`/api/books/${id}`),
    create: (book: BookInput) => post<{ book: Book }>('/api/books', book),
    update: (id: string, book: Partial<BookInput>) => patch<{ book: Book }>(`/api/books/${id}`, book),
    remove: (id: string) => del<{ ok: true }>(`/api/books/${id}`),
  },

  checkouts: {
    list: () =>
      get<{ checkouts: CheckoutItem[]; summary: { active: number; overdue: number; returned: number; tampered: number } }>(
        '/api/checkouts',
      ),
    borrow: (bookId: string) => post<{ checkout: any; encrypted: { ciphertext: string; hmacTag: string } }>('/api/checkouts', { bookId }),
    return: (id: string) => post<{ returned: true; daysOverdue: number; fine: (FineComputation & { id: string }) | null }>(`/api/checkouts/${id}/return`),
  },

  fines: {
    list: () => get<{ fines: FineItem[]; summary: FineSummary }>('/api/fines'),
    pay: (id: string) => post<{ ok: true; paid: number; summary: FineSummary }>(`/api/fines/${id}/pay`),
    payAll: () => post<{ ok: true; paid: number; count: number; summary: FineSummary }>('/api/fines/pay-all'),
  },

  reviews: {
    list: () => get<{ reviews: ReviewItem[]; count: number }>('/api/reviews'),
    eligible: () => get<{ books: EligibleBook[] }>('/api/reviews/eligible'),
    create: (review: { bookId: string; rating: number; body: string }) => post<{ review: ReviewItem }>('/api/reviews', review),
    update: (id: string, review: { rating?: number; body?: string }) => patch<{ review: ReviewItem }>(`/api/reviews/${id}`, review),
    remove: (id: string) => del<{ ok: true }>(`/api/reviews/${id}`),
  },

  chat: {
    threads: () => get<{ threads: ChatThread[] }>('/api/chat/threads'),
    messages: (peerId: string) =>
      get<{ messages: ChatMessage[]; peer: { id: string; username: string; role: Role } }>(`/api/chat/messages?peerId=${peerId}`),
    send: (peerId: string, body: string) => post<{ message: ChatMessage }>('/api/chat/messages', { peerId, body }),
  },

  profile: {
    get: () => get<ProfileResponse>('/api/profile'),
    update: (fields: Partial<ProfileFields>) => put<{ ok: true; reEncrypted: string[] }>('/api/profile', fields),
  },

  keys: {
    get: () => get<KeyInfo>('/api/keys'),
    rotate: (password: string) => post<RotationResponse>('/api/keys/rotate', { password }),
  },

  admin: {
    stats: () => get<AdminStats>('/api/admin/stats'),
    users: () => get<{ users: AdminUser[]; note: string }>('/api/admin/users'),
    setUserStatus: (id: string, status: 'active' | 'suspended') =>
      patch<{ ok: true; username: string; status: string }>(`/api/admin/users/${id}/status`, { status }),
    fines: () => get<{ fines: AdminFine[]; summary: FineSummary }>('/api/admin/fines'),
    audit: (params: { event?: string; outcome?: string; username?: string; limit?: string } = {}) =>
      get<{ events: AuditEntry[]; eventTypes: string[] }>(`/api/admin/audit${qs(params)}`),
    encrypted: (table: EncryptedTable) =>
      get<{ table: string; columns: string[]; rows: EncryptedRow[]; note: string }>(`/api/admin/encrypted/${table}`),
  },

  lab: {
    selfTest: () =>
      get<{ verdict: string; passed: number; total: number; results: SelfTestResult[]; note: string }>('/api/lab/self-test'),
    tamper: (table: string, id: string) =>
      post<{ ok: true; before: string; after: string; note: string }>('/api/lab/tamper', { table, id }),
  },

  health: () => get<any>('/api/health'),
}
