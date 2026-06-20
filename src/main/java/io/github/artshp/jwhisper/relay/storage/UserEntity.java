package io.github.artshp.jwhisper.relay.storage;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * User entity in database.
 * @param id user id
 * @param username username
 * @param publicSigningKey public signing key (encoded)
 * @param publicEncryptionKey public encryption key (encoded)
 * @param registeredAt timestamp when user was registered
 */
@Table("JW_USERS")
public record UserEntity(
        @Id Long id,
        String username,
        byte[] publicSigningKey,
        byte[] publicEncryptionKey,
        Instant registeredAt
) {

    /**
     * Create a new user entity with auto-generated id (auto-increment).
     * @param username username
     * @param publicSigningKey public signing key (encoded)
     * @param publicEncryptionKey public encryption key (encoded)
     * @param registeredAt timestamp when user was registered
     */
    public UserEntity(String username, byte[] publicSigningKey, byte[] publicEncryptionKey, Instant registeredAt) {
        this(null, username, publicSigningKey, publicEncryptionKey, registeredAt);
    }
}
