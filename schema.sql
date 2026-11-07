-- TrustVault schema (audit_log is created by audit.py)
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS categories (
    id       SERIAL PRIMARY KEY,
    name     TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    UNIQUE (owner_id, name)
);

CREATE TABLE IF NOT EXISTS documents (
    id            SERIAL PRIMARY KEY,
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    category_id   INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    original_name TEXT NOT NULL,
    stored_name   TEXT NOT NULL UNIQUE,   -- random name on disk, never the user's filename
    mime_type     TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Levels: view (open in browser only) < download (view + download) < edit (view + download + edit).
-- Revoking = deleting the row, so access stops on the very next request.
CREATE TABLE IF NOT EXISTS permissions (
    id           SERIAL PRIMARY KEY,
    document_id  INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    access_level TEXT NOT NULL CHECK (access_level IN ('view','download','edit')),
    granted_by   INTEGER NOT NULL REFERENCES users(id),
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, user_id)
);

-- Only used when STORAGE_BACKEND=db (hosts with an ephemeral disk). Never exposed by any route.
CREATE TABLE IF NOT EXISTS file_blobs (
    stored_name TEXT PRIMARY KEY,
    data        BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents (owner_id);
CREATE INDEX IF NOT EXISTS idx_perm_user  ON permissions (user_id);

-- Password reset support (idempotent, safe to re-run on an existing database).
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;   -- bump = all sessions die
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested_at TIMESTAMPTZ;

-- Email login (idempotent). Existing accounts keep working with their username until
-- they add an email under Account > Email. NULLs are allowed; real emails are unique.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (email);

-- Separate view / download permissions (idempotent migration of older databases):
-- the old 'read' level meant view + download, which is exactly the new 'download' level.
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_access_level_check;
UPDATE permissions SET access_level = 'download' WHERE access_level = 'read';
ALTER TABLE permissions ADD CONSTRAINT permissions_access_level_check
    CHECK (access_level IN ('view','download','edit'));
