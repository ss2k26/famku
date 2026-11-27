-- famku schema v2: unique username per user (sign in with username or email).
-- Existing rows get a placeholder ("user" + the first 10 characters of the id); the owner can change it in the profile.

ALTER TABLE users ADD COLUMN username VARCHAR(30) NULL AFTER email;

UPDATE users SET username = CONCAT('user', SUBSTRING(id, 1, 10)) WHERE username IS NULL;

ALTER TABLE users MODIFY username VARCHAR(30) NOT NULL, ADD UNIQUE KEY uq_users_username (username);
