export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

export function fmtDate(value?: string | number | null, withTime = false): string {
  if (!value) return '—'
  const date = typeof value === 'number' ? new Date(value) : new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}),
  })
}

export function fmtTime(value?: string | number | null): string {
  if (!value) return '—'
  const date = new Date(value)
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

export function fmtBDT(amount: number | string | null | undefined): string {
  const value = Number(amount ?? 0)
  return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} BDT`
}

export function relativeTime(value?: string | number | null): string {
  if (!value) return '—'
  const then = new Date(value).getTime()
  if (Number.isNaN(then)) return '—'
  const diff = Date.now() - then
  const abs = Math.abs(diff)
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [1000, 'second'],
    [60_000, 'minute'],
    [3_600_000, 'hour'],
    [86_400_000, 'day'],
    [604_800_000, 'week'],
    [2_629_800_000, 'month'],
    [31_557_600_000, 'year'],
  ]
  let chosen: [number, Intl.RelativeTimeFormatUnit] = units[0]
  for (const unit of units) if (abs >= unit[0]) chosen = unit
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  return formatter.format(Math.round(-diff / chosen[0]), chosen[1])
}

/** Whole days until a date; negative once it is in the past. */
export function daysUntil(dateISO?: string | null): number {
  if (!dateISO) return 0
  const due = new Date(`${dateISO.slice(0, 10)}T23:59:59.999Z`).getTime()
  return Math.ceil((due - Date.now()) / 86_400_000)
}

export function initials(name: string): string {
  return name.slice(0, 2).toUpperCase()
}

export function truncate(value: string, length = 64): string {
  return value.length <= length ? value : `${value.slice(0, length)}…`
}

/** Turns an audit event_type into something readable. */
export function humanEvent(eventType: string): string {
  return eventType.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase())
}
