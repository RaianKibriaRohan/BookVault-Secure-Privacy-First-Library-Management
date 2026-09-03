# Demo accounts

Two accounts are already provisioned in the connected Supabase project, both
created through the normal cryptographic path (salted password hash, RSA-2048 +
secp256k1 key pair, wrapped private material, RSA-encrypted profile, CBC-MAC).

| Role | Username | Password | TOTP secret (base32) |
|---|---|---|---|
| Head Librarian | `librarian` | `Vault-Admin-2026` | `7GUFNJCTP4SUYXPDAWVHO5KW46ZA3L4E` |
| Patron | `faiza` | `Reading-Room-77` | `H3EKRBNZTEIFINLIASODN2IRMWOZOZT5` |

## Signing in

Sign-in takes two factors. After the password step, you need the current
six-digit code. Either:

- add the base32 secret above to an authenticator app (Google Authenticator,
  Aegis, 1Password — set the algorithm to **SHA-256**, 6 digits, 30 seconds), or
- click **Show current code** on the second-factor screen. That button appears
  only while `ENABLE_LAB_ROUTES=true` in `server/.env`, and it exists so the app
  can be demonstrated without an authenticator to hand.

The otpauth URIs, if you want to paste them into an app directly:

```
otpauth://totp/BookVault%3Alibrarian?secret=7GUFNJCTP4SUYXPDAWVHO5KW46ZA3L4E&issuer=BookVault&algorithm=SHA256&digits=6&period=30
```

```
otpauth://totp/BookVault%3Afaiza?secret=H3EKRBNZTEIFINLIASODN2IRMWOZOZT5&issuer=BookVault&algorithm=SHA256&digits=6&period=30
```

## Creating more accounts

- Patrons register themselves at `/register`. The TOTP secret is displayed once,
  immediately after registration, and is never retrievable again — it is stored
  only in wrapped form.
- Another librarian:

```bash
npm run seed:admin -- --username second-librarian --password "some-strong-password"
```

## Notes

- Only one session per account is live at a time. Signing in from a second
  browser revokes the first — that is single-session enforcement, not a bug.
- Restarting the API drops the in-memory key vault, so everyone must sign in
  again. Private keys are never persisted in usable form; this is the cost of
  that guarantee.
- These credentials are for a local lab project. Re-seed with fresh passwords
  before showing the system to anyone you would not hand this file to.
