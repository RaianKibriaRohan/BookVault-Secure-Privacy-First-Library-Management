#!/usr/bin/env node
/**
 * Applies db/schema.sql to the Supabase project through the Management API.
 *
 *   SUPABASE_ACCESS_TOKEN=sbp_xxx SUPABASE_PROJECT_REF=xxxx node scripts/apply-schema.mjs
 *
 * Both values can also be placed in a .env file at the repository root.
 * WARNING: schema.sql begins with `drop table if exists ... cascade` — running
 * this against a populated database destroys all rows.
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

// minimal .env loader (root/.env) so the script has no dependencies
if (existsSync(join(root, '.env'))) {
  for (const line of readFileSync(join(root, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim()
  }
}

const token = process.env.SUPABASE_ACCESS_TOKEN
const ref = process.env.SUPABASE_PROJECT_REF

if (!token || !ref) {
  console.error('Missing SUPABASE_ACCESS_TOKEN or SUPABASE_PROJECT_REF.')
  console.error('Alternatively paste db/schema.sql into the Supabase SQL editor.')
  process.exit(1)
}

const sql = readFileSync(join(root, 'db', 'schema.sql'), 'utf8')

const res = await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ query: sql }),
})

const body = await res.text()
if (!res.ok) {
  console.error(`Schema push failed (${res.status}):`, body)
  process.exit(1)
}
console.log('Schema applied to project', ref)
console.log(body.slice(0, 400))
