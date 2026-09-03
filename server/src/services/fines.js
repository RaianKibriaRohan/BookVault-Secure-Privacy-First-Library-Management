/**
 * Overdue fine policy (feature F5).
 *
 *   days 1-7    5 BDT/day
 *   days 8-14   10 BDT/day
 *   day 15+     20 BDT/day, plus a book replacement notice
 *
 * Worked example from the proposal: due 1 Aug, returned 19 Aug = 18 days late
 *   (7 x 5) + (7 x 10) + (4 x 20) = 35 + 70 + 80 = 185 BDT + replacement notice
 */
export const FINE_TIERS = Object.freeze([
  Object.freeze({ tier: '1-7 days', from: 1, to: 7, rate: 5 }),
  Object.freeze({ tier: '8-14 days', from: 8, to: 14, rate: 10 }),
  Object.freeze({ tier: '15+ days', from: 15, to: Infinity, rate: 20 }),
])

export const REPLACEMENT_THRESHOLD = 15

export function computeFine(daysOverdue) {
  const days = Math.max(0, Math.floor(Number(daysOverdue) || 0))
  const breakdown = []
  let amount = 0

  for (const tier of FINE_TIERS) {
    if (days < tier.from) break
    const daysInTier = Math.min(days, tier.to) - tier.from + 1
    if (daysInTier <= 0) continue
    const subtotal = daysInTier * tier.rate
    amount += subtotal
    breakdown.push({ tier: tier.tier, days: daysInTier, rate: tier.rate, subtotal })
  }

  return {
    amount,
    daysOverdue: days,
    replacementNotice: days >= REPLACEMENT_THRESHOLD,
    currency: 'BDT',
    breakdown,
  }
}

/**
 * Whole days late. A book handed back on its due date is not overdue, so the
 * clock starts at the end of the due date.
 */
export function daysBetween(dueDateISO, returnedAtISO = new Date().toISOString()) {
  const due = new Date(`${String(dueDateISO).slice(0, 10)}T23:59:59.999Z`).getTime()
  const returned = new Date(returnedAtISO).getTime()
  if (!Number.isFinite(due) || !Number.isFinite(returned)) return 0
  if (returned <= due) return 0
  return Math.ceil((returned - due) / 86_400_000)
}

/**
 * Whole days remaining before the due date, negative once overdue.
 *
 * Compared calendar date to calendar date rather than timestamp to timestamp:
 * a book due in fourteen days should read "14", not "15" merely because the
 * due date runs to the end of its day.
 */
export function daysUntilDue(dueDateISO, nowISO = new Date().toISOString()) {
  const due = Date.parse(`${String(dueDateISO).slice(0, 10)}T00:00:00.000Z`)
  const today = Date.parse(`${String(nowISO).slice(0, 10)}T00:00:00.000Z`)
  if (!Number.isFinite(due) || !Number.isFinite(today)) return 0
  return Math.round((due - today) / 86_400_000)
}

export function addDays(days, fromISO = new Date().toISOString()) {
  const base = new Date(fromISO)
  base.setUTCDate(base.getUTCDate() + days)
  return base.toISOString().slice(0, 10)
}
