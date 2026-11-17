-- webservco/auth table for MariaDB and MySQL. Times are Unix seconds.
-- The application's own account table is only read (and its password column updated on rehash).
-- Binary collation: account ids compare exactly, as in the SQLite tests.

CREATE TABLE auth_account_state (
    realm VARCHAR(32) NOT NULL,
    account_id VARCHAR(64) NOT NULL,
    epoch INT UNSIGNED NOT NULL DEFAULT 0,
    failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until INT UNSIGNED NULL,
    last_login_at INT UNSIGNED NULL,
    PRIMARY KEY (realm, account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Remember-me tokens, only for realms that use remember-me. The validator is stored as its SHA-256 (hex).
CREATE TABLE auth_remember_token (
    selector CHAR(32) NOT NULL,
    realm VARCHAR(32) NOT NULL,
    account_id VARCHAR(64) NOT NULL,
    validator_hash CHAR(64) NOT NULL,
    epoch INT UNSIGNED NOT NULL,
    expires_at INT UNSIGNED NOT NULL,
    created_at INT UNSIGNED NOT NULL,
    PRIMARY KEY (selector),
    KEY realm_account (realm, account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
