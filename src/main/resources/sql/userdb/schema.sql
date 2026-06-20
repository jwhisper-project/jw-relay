CREATE TABLE IF NOT EXISTS jw_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    public_signing_key BINARY(32) NOT NULL,
    public_encryption_key BINARY(32) NOT NULL,
    registered_at TIMESTAMP NOT NULL
);