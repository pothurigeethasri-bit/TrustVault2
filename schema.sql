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

-- Revoking = deleting the row, so access stops on the very next request.
CREATE TABLE IF NOT EXISTS permissions (
    id           SERIAL PRIMARY KEY,
    document_id  INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    access_level TEXT NOT NULL CHECK (access_level IN ('read','edit')),
    granted_by   INTEGER NOT NULL REFERENCES users(id),
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents (owner_id);
CREATE INDEX IF NOT EXISTS idx_perm_user  ON permissions (user_id);
