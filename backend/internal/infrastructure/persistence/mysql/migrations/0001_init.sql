-- famku schema v1 (MySQL 8.x / MariaDB 10.6+). All identifiers and hashes use utf8mb4_bin (exact match).

CREATE TABLE users (
  id               CHAR(32)     NOT NULL,
  email            VARCHAR(254) NOT NULL,
  name             VARCHAR(80)  NOT NULL,
  password_hash    VARCHAR(255) NOT NULL,
  email_verified_at DATETIME(6) NULL,
  totp_secret      VARCHAR(64)  NOT NULL DEFAULT '',
  totp_enabled     TINYINT(1)   NOT NULL DEFAULT 0,
  totp_last_step   BIGINT       NOT NULL DEFAULT 0,
  created_at       DATETIME(6)  NOT NULL,
  updated_at       DATETIME(6)  NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sessions (
  id           CHAR(32)     NOT NULL,
  user_id      CHAR(32)     NOT NULL,
  token_hash   CHAR(64)     NOT NULL,
  csrf_token   VARCHAR(64)  NOT NULL,
  user_agent   VARCHAR(255) NOT NULL DEFAULT '',
  ip           VARCHAR(45)  NOT NULL DEFAULT '',
  created_at   DATETIME(6)  NOT NULL,
  last_seen_at DATETIME(6)  NOT NULL,
  expires_at   DATETIME(6)  NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_token (token_hash),
  KEY idx_sessions_user (user_id),
  KEY idx_sessions_expires (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE one_time_tokens (
  id         CHAR(32)    NOT NULL,
  user_id    CHAR(32)    NOT NULL,
  purpose    VARCHAR(32) NOT NULL,
  token_hash CHAR(64)    NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  used_at    DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tokens_hash (token_hash),
  KEY idx_tokens_user (user_id, purpose),
  KEY idx_tokens_expires (expires_at),
  CONSTRAINT fk_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE recovery_codes (
  id        CHAR(32)    NOT NULL,
  user_id   CHAR(32)    NOT NULL,
  code_hash CHAR(64)    NOT NULL,
  used_at   DATETIME(6) NULL,
  PRIMARY KEY (id),
  KEY idx_recovery_lookup (user_id, code_hash),
  CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE audit_events (
  id         CHAR(32)     NOT NULL,
  user_id    CHAR(32)     NULL,
  action     VARCHAR(40)  NOT NULL,
  ip         VARCHAR(45)  NOT NULL DEFAULT '',
  user_agent VARCHAR(255) NOT NULL DEFAULT '',
  detail     VARCHAR(255) NOT NULL DEFAULT '',
  created_at DATETIME(6)  NOT NULL,
  PRIMARY KEY (id),
  KEY idx_audit_user (user_id, created_at),
  KEY idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
