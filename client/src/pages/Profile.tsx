import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ApiError, type ProfileFields, type ProfileResponse } from '../lib/api'
import {
  Badge,
  Button,
  Card,
  Cipher,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  KeysLocked,
  PageHeader,
  ShieldIcon,
  Spinner,
  useToast,
} from '../components/ui'
import { useReSignIn } from '../context/AuthContext'
import { fmtDate } from '../lib/format'

const FIELDS: { key: keyof ProfileFields; label: string; hint?: string; type?: string }[] = [
  { key: 'fullName', label: 'Full name' },
  { key: 'email', label: 'Email', type: 'email' },
  { key: 'phone', label: 'Phone' },
  { key: 'libraryCard', label: 'Library card number' },
  { key: 'address', label: 'Address' },
]

export default function Profile() {
  const toast = useToast()
  const reSignIn = useReSignIn()
  const [locked, setLocked] = useState(false)
  const [data, setData] = useState<ProfileResponse | null>(null)
  const [form, setForm] = useState<ProfileFields | null>(null)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showStored, setShowStored] = useState(false)

  const load = useCallback(async () => {
    try {
      const response = await api.profile.get()
      setData(response)
      setForm(response.fields)
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'KEYS_LOCKED') setLocked(true)
      else setError(err instanceof ApiError ? err.message : 'Could not open your profile.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const dirty = useMemo(() => {
    if (!data || !form) return []
    return FIELDS.map(f => f.key).filter(key => (form[key] ?? '') !== (data.fields[key] ?? ''))
  }, [data, form])

  const save = async () => {
    if (!form || dirty.length === 0) return
    setSaving(true)
    try {
      const changes: Partial<ProfileFields> = {}
      for (const key of dirty) changes[key] = form[key] ?? ''
      const result = await api.profile.update(changes)
      toast.push(`Re-encrypted and re-tagged: ${result.reEncrypted.join(', ')}.`, 'success')
      setEditing(false)
      await load()
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not save your profile.', 'error')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-muted">
        <Spinner size={22} />
      </div>
    )
  }

  if (locked) return <KeysLocked onSignOut={reSignIn} />

  if (!data || !form) return <ErrorNote>{error ?? 'Profile unavailable.'}</ErrorNote>

  return (
    <>
      <PageHeader
        title="Profile"
        subtitle="Every field below is encrypted individually with your own RSA-2048 public key, and the whole encrypted blob is covered by one CBC-MAC tag."
        actions={
          editing ? (
            <>
              <Button
                variant="ghost"
                onClick={() => {
                  setForm(data.fields)
                  setEditing(false)
                }}
              >
                Cancel
              </Button>
              <Button loading={saving} disabled={dirty.length === 0} onClick={save}>
                {dirty.length === 0 ? 'No changes' : `Re-encrypt ${dirty.length} field${dirty.length > 1 ? 's' : ''}`}
              </Button>
            </>
          ) : (
            <Button onClick={() => setEditing(true)}>Edit profile</Button>
          )
        }
      />

      {/* MAC banner */}
      <div
        className={
          data.macValid
            ? 'mb-5 flex items-start gap-3 rounded-xl2 border border-accent/30 bg-accent/8 p-4'
            : 'mb-5 flex items-start gap-3 rounded-xl2 border border-danger/40 bg-danger/8 p-4'
        }
      >
        <div className={data.macValid ? 'mt-0.5 text-accent' : 'mt-0.5 text-danger'}>
          <ShieldIcon size={18} />
        </div>
        <div>
          <div className={data.macValid ? 'text-sm font-medium text-accent' : 'text-sm font-medium text-danger'}>
            {data.macValid ? 'CBC-MAC verified' : 'CBC-MAC verification failed'}
          </div>
          <p className="mt-1 text-sm text-muted">
            {data.macValid
              ? 'The stored profile blob matches its integrity tag, so nothing has been altered in the database since you last saved.'
              : 'The stored profile no longer matches its tag. One or more encrypted fields have been changed outside this application. Contact the librarian before saving anything further.'}
          </p>
        </div>
      </div>

      {!data.decryptable && (
        <ErrorNote className="mb-5">
          At least one field could not be decrypted with your current key version. If you have just rotated your keys,
          sign out and back in.
        </ErrorNote>
      )}

      <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
        <Card className="p-5">
          <div className="space-y-4">
            {FIELDS.map(field => (
              <Field key={field.key} label={field.label}>
                {editing ? (
                  <Input
                    type={field.type ?? 'text'}
                    value={form[field.key] ?? ''}
                    onChange={e => setForm(current => (current ? { ...current, [field.key]: e.target.value } : current))}
                  />
                ) : (
                  <div className="rounded-lg border border-line bg-ink/40 px-3 py-2 text-sm text-slate-200">
                    {data.fields[field.key] || <span className="text-faint">not set</span>}
                  </div>
                )}
              </Field>
            ))}
          </div>

          {editing && dirty.length > 0 && (
            <InfoNote className="mt-4" tone="accent">
              {dirty.length} field{dirty.length > 1 ? 's' : ''} changed. Saving re-encrypts{' '}
              {dirty.length > 1 ? 'them' : 'it'} with RSA and recomputes the CBC-MAC over the whole profile.
            </InfoNote>
          )}

          <div className="mt-5 flex flex-wrap gap-2 border-t border-line pt-4 text-xs text-faint">
            <Badge tone="neutral">key version {data.keyVersion}</Badge>
            <span>Last updated {fmtDate(data.updatedAt, true)}</span>
          </div>
        </Card>

        <Card className="h-fit p-5">
          <div className="flex items-center justify-between">
            <div className="text-[11px] font-medium uppercase tracking-wider text-faint">What the database holds</div>
            <Button size="sm" variant="ghost" onClick={() => setShowStored(v => !v)}>
              {showStored ? 'Hide' : 'Show'}
            </Button>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted">
            These are the actual column values for your row. Each is an RSA-OAEP ciphertext of a single field, encrypted
            under your own public key.
          </p>

          {showStored && (
            <div className="mt-3 space-y-2">
              {FIELDS.map(field => (
                <Cipher key={field.key} label={`${field.key}_enc`} value={data.ciphertext[field.key]} />
              ))}
              <Cipher label="profile_mac (CBC-MAC)" value={data.profileMac} />
            </div>
          )}
        </Card>
      </div>
    </>
  )
}
