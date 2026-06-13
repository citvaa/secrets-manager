-- Oblak — seed/schema script (SQLite dialect).
-- The project description allows entering data via SQL instead of building a
-- front-end. Tables match the ORM models in app/models.py.
--
-- NOTE: passwords are stored ONLY as Argon2id hashes (req. ZR-A2). To create the
-- demo user below, generate a hash with:
--     python -c "from app.security import hash_password; print(hash_password('CorrectHorseBatteryStaple'))"
-- and paste it into the INSERT. Do NOT put plaintext passwords here.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS functions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users(id),
    name         VARCHAR(64) NOT NULL,
    code_sha256  VARCHAR(64) NOT NULL,
    storage_path VARCHAR(512) NOT NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'UPLOADED',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (owner_id, name)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         DATETIME DEFAULT CURRENT_TIMESTAMP,
    actor      VARCHAR(64) NOT NULL DEFAULT '-',
    action     VARCHAR(64) NOT NULL,
    resource   VARCHAR(255) NOT NULL DEFAULT '-',
    outcome    VARCHAR(16) NOT NULL,
    request_id VARCHAR(36) NOT NULL DEFAULT '-',
    client_ip  VARCHAR(64) NOT NULL DEFAULT '-',
    detail     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ix_functions_owner_id ON functions(owner_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_ts ON audit_events(ts);

-- Example admin user (fill in a real Argon2 hash before running):
-- INSERT INTO users (username, password_hash, is_admin)
-- VALUES ('admin', '$argon2id$v=19$m=65536,t=3,p=4$....', 1);
