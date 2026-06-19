CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(255) PRIMARY KEY,
    public_signing_key BINARY(32) NOT NULL,
    public_encryption_key BINARY(32) NOT NULL,
    registered_at TIMESTAMP NOT NULL
);