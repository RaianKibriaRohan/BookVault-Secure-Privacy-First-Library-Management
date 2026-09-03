-- ============================================================================
-- BookVault - Secure Privacy-First Library Management
-- CSE447 Lab Project | Choice 2
--
-- PostgreSQL schema (Supabase). The database stores ONLY:
--   ciphertext, MAC tags, salted hashes, and non-sensitive metadata.
-- No plaintext patron data ever reaches this schema.
--
-- Supabase is used purely as a PostgreSQL store. supabase.auth, RLS policies
-- and Edge Functions are intentionally NOT used - every authentication,
-- encryption and access-control decision happens in the Express backend.
-- ============================================================================

drop table if exists audit_logs      cascade;
drop table if exists chat_messages   cascade;
drop table if exists reviews         cascade;
drop table if exists fines           cascade;
drop table if exists checkouts       cascade;
drop table if exists sessions        cascade;
drop table if exists user_keys       cascade;
drop table if exists books           cascade;
drop table if exists users           cascade;

-- ---------------------------------------------------------------------------
-- users
--   password : custom SHA-256(salt || password); salt and hash stored apart
--   profile  : every field individually RSA-encrypted under the user's own
--              public key, plus one CBC-MAC tag over the whole profile blob
--   totp     : shared secret, key-wrapped with a password-derived mask so a
--              database dump alone cannot forge OTP codes
-- ---------------------------------------------------------------------------
create table users (
    id                    uuid primary key default gen_random_uuid(),
    username              text        not null unique,
    role                  text        not null default 'patron'
                                      check (role in ('patron', 'admin')),
    status                text        not null default 'active'
                                      check (status in ('active', 'suspended')),

    -- F1: salted hash, custom SHA-256
    password_salt         text        not null,   -- 128-bit salt, hex
    password_hash         text        not null,   -- SHA-256(salt||pw), hex

    -- F1 / 2FA: HMAC-TOTP shared secret, wrapped with password-derived mask
    totp_secret_wrapped   text        not null,

    -- F9: RSA-encrypted profile fields (hex ciphertext, user's own public key)
    email_enc             text,
    phone_enc             text,
    library_card_enc      text,
    full_name_enc         text,
    address_enc           text,

    -- F6 / F9: CBC-MAC tag over the concatenated profile ciphertext blob
    profile_mac           text,

    key_version           int         not null default 1,
    failed_logins         int         not null default 0,
    last_login_at         timestamptz,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- user_keys - Key Management Module storage (F10 / Security Feature 4)
--   Private components are key-wrapped with a mask derived from the user's
--   password, so neither the admin nor a database leak yields usable keys.
--   Rotation inserts a new row (version + 1) and retires the previous one.
-- ---------------------------------------------------------------------------
create table user_keys (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        not null references users(id) on delete cascade,
    version               int         not null,

    -- RSA-2048 (profile + chat)
    rsa_n                 text        not null,   -- modulus, hex
    rsa_e                 text        not null,   -- public exponent, hex
    rsa_d_wrapped         text        not null,   -- private exponent, wrapped

    -- ECC secp256k1 (checkout records, reviews, fines)
    ecc_pub_x             text        not null,
    ecc_pub_y             text        not null,
    ecc_priv_wrapped      text        not null,

    -- 256-bit MAC key for HMAC-SHA256 / CBC-MAC over the user's own records
    mac_key_wrapped       text        not null,

    created_at            timestamptz not null default now(),
    retired_at            timestamptz,
    unique (user_id, version)
);
create index user_keys_user_idx on user_keys (user_id, version desc);

-- ---------------------------------------------------------------------------
-- books - the catalog. Explicitly NOT sensitive, stored in plaintext (F2).
-- ---------------------------------------------------------------------------
create table books (
    id                    uuid primary key default gen_random_uuid(),
    title                 text        not null,
    author                text        not null,
    isbn                  text        not null unique,
    genre                 text        not null,
    description           text        not null default '',
    published_year        int,
    total_copies          int         not null default 1 check (total_copies >= 0),
    available_copies      int         not null default 1 check (available_copies >= 0),
    cover_hue             int         not null default 210,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now()
);
create index books_title_idx  on books (lower(title));
create index books_author_idx on books (lower(author));
create index books_genre_idx  on books (lower(genre));

-- ---------------------------------------------------------------------------
-- checkouts - the encrypted "posts" (F3 / F4 / F6)
--   ciphertext = ECIES(secp256k1) over
--                {book_id, book_title, author, checkout_date, due_date, status}
--
--   NOTE: book_id is deliberately NOT stored in plaintext. The admin can see
--   that a checkout exists and when it is due, but never WHICH book it is.
--   due_date + status are mirrored in plaintext so the server can enforce due
--   dates and compute fines without ever decrypting the record.
-- ---------------------------------------------------------------------------
create table checkouts (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        not null references users(id) on delete cascade,
    ciphertext            text        not null,
    hmac_tag              text        not null,
    key_version           int         not null default 1,

    checkout_date         date        not null default current_date,
    due_date              date        not null,
    status                text        not null default 'active'
                                      check (status in ('active', 'returned')),
    returned_at           timestamptz,
    tampered              boolean     not null default false,
    created_at            timestamptz not null default now()
);
create index checkouts_user_idx on checkouts (user_id, status);
create index checkouts_due_idx  on checkouts (due_date);

-- ---------------------------------------------------------------------------
-- fines - encrypted fine records (F5). Amount / days overdue / status are
-- plaintext because A3 requires an admin fine dashboard; the record body
-- (which book, which checkout, the breakdown) stays encrypted.
-- ---------------------------------------------------------------------------
create table fines (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        not null references users(id) on delete cascade,
    checkout_id           uuid        references checkouts(id) on delete set null,
    ciphertext            text        not null,
    hmac_tag              text        not null,
    key_version           int         not null default 1,

    amount                numeric(10,2) not null check (amount >= 0),
    days_overdue          int         not null default 0,
    status                text        not null default 'unpaid'
                                      check (status in ('unpaid', 'paid')),
    replacement_notice    boolean     not null default false,
    tampered              boolean     not null default false,
    created_at            timestamptz not null default now(),
    paid_at               timestamptz
);
create index fines_user_idx on fines (user_id, status);

-- ---------------------------------------------------------------------------
-- reviews - private book reviews (F7). Book identity lives inside the
-- ciphertext, so not even the review's subject is visible to the admin.
-- ---------------------------------------------------------------------------
create table reviews (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        not null references users(id) on delete cascade,
    ciphertext            text        not null,
    hmac_tag              text        not null,
    key_version           int         not null default 1,
    tampered              boolean     not null default false,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now()
);
create index reviews_user_idx on reviews (user_id);

-- ---------------------------------------------------------------------------
-- chat_messages - secure patron <-> librarian chat (F8 / A4)
--   body_for_recipient : RSA-OAEP under the RECIPIENT's public key
--   body_for_sender    : RSA-OAEP under the SENDER's own public key, so the
--                        sender can still render their own outbox. Neither
--                        copy is readable by the server or by a third party.
--   hmac_tag           : HMAC-SHA256(ECDH(sender_priv, recipient_pub),
--                        body_for_recipient || ts) - authenticity + replay
--                        protection through the bound timestamp.
-- ---------------------------------------------------------------------------
create table chat_messages (
    id                    uuid primary key default gen_random_uuid(),
    sender_id             uuid        not null references users(id) on delete cascade,
    recipient_id          uuid        not null references users(id) on delete cascade,
    body_for_recipient    text        not null,
    body_for_sender       text        not null,
    hmac_tag              text        not null,
    ts                    bigint      not null,   -- unix ms, bound into the MAC
    sender_key_version    int         not null default 1,
    recipient_key_version int         not null default 1,
    read_at               timestamptz,
    created_at            timestamptz not null default now()
);
create index chat_pair_idx      on chat_messages (sender_id, recipient_id, ts);
create index chat_recipient_idx on chat_messages (recipient_id, ts desc);

-- ---------------------------------------------------------------------------
-- sessions - secure session management (Security Feature 9)
--   Only the SHA-256 hash of the token is stored; the raw token lives in an
--   HttpOnly cookie. IP + user-agent fingerprints detect hijacking.
-- ---------------------------------------------------------------------------
create table sessions (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        not null references users(id) on delete cascade,
    token_hash            text        not null unique,
    ip_fingerprint        text        not null,
    ua_fingerprint        text        not null,
    created_at            timestamptz not null default now(),
    last_active_at        timestamptz not null default now(),
    expires_at            timestamptz not null,
    revoked               boolean     not null default false,
    revoked_reason        text
);
create index sessions_user_idx on sessions (user_id, revoked);

-- ---------------------------------------------------------------------------
-- audit_logs - A5. Metadata only; never encrypted or decrypted content.
-- ---------------------------------------------------------------------------
create table audit_logs (
    id                    uuid primary key default gen_random_uuid(),
    user_id               uuid        references users(id) on delete set null,
    username              text,
    event_type            text        not null,
    outcome               text        not null default 'success'
                                      check (outcome in ('success', 'failure', 'warning')),
    detail                text        not null default '',
    ip                    text,
    created_at            timestamptz not null default now()
);
create index audit_created_idx on audit_logs (created_at desc);
create index audit_event_idx   on audit_logs (event_type);

-- ---------------------------------------------------------------------------
-- Catalog seed (non-sensitive data only)
-- ---------------------------------------------------------------------------
insert into books (title, author, isbn, genre, description, published_year, total_copies, available_copies, cover_hue) values
 ('Applied Cryptography', 'Bruce Schneier', '9780471117094', 'Cryptography', 'Protocols, algorithms and source code in C - the classic field guide to practical cryptography.', 1996, 3, 3, 205),
 ('The Code Book', 'Simon Singh', '9780385495325', 'Cryptography', 'The evolution of secrecy from Mary Queen of Scots to quantum cryptography.', 1999, 2, 2, 265),
 ('Introduction to Algorithms', 'Cormen, Leiserson, Rivest, Stein', '9780262046305', 'Computer Science', 'The canonical algorithms text, covering data structures, graphs and NP-completeness.', 2022, 4, 4, 150),
 ('Security Engineering', 'Ross Anderson', '9781119642787', 'Security', 'A guide to building dependable distributed systems, third edition.', 2020, 2, 2, 15),
 ('Clean Code', 'Robert C. Martin', '9780132350884', 'Software Engineering', 'A handbook of agile software craftsmanship.', 2008, 3, 3, 95),
 ('Designing Data-Intensive Applications', 'Martin Kleppmann', '9781449373320', 'Distributed Systems', 'The big ideas behind reliable, scalable and maintainable systems.', 2017, 2, 2, 35),
 ('The Pragmatic Programmer', 'Hunt and Thomas', '9780135957059', 'Software Engineering', 'Your journey to mastery, 20th anniversary edition.', 2019, 3, 3, 120),
 ('Cryptography Engineering', 'Ferguson, Schneier, Kohno', '9780470474242', 'Cryptography', 'Design principles and practical applications for real-world crypto systems.', 2010, 2, 2, 240),
 ('Computer Networks', 'Andrew S. Tanenbaum', '9780132126953', 'Networking', 'A systematic, layered approach to modern computer networking.', 2010, 2, 2, 175),
 ('Operating System Concepts', 'Silberschatz, Galvin, Gagne', '9781118063330', 'Computer Science', 'The dinosaur book - processes, memory, storage and protection.', 2012, 3, 3, 25),
 ('Sapiens: A Brief History of Humankind', 'Yuval Noah Harari', '9780062316097', 'History', 'From the cognitive revolution to the biotechnology age.', 2011, 2, 2, 45),
 ('Nineteen Eighty-Four', 'George Orwell', '9780451524935', 'Fiction', 'A dystopia of total surveillance - required reading for a privacy-first library.', 1949, 4, 4, 0),
 ('The Design of Everyday Things', 'Don Norman', '9780465050659', 'Design', 'Why some products satisfy and others frustrate.', 2013, 2, 2, 320),
 ('Thinking, Fast and Slow', 'Daniel Kahneman', '9780374533557', 'Psychology', 'The two systems that drive the way we think.', 2011, 2, 2, 285),
 ('Structure and Interpretation of Computer Programs', 'Abelson and Sussman', '9780262510875', 'Computer Science', 'The wizard book - programs as abstractions over process.', 1996, 2, 2, 340);
