package io.github.artshp.jwhisper.relay.storage;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("JW_USERS")
public record UserEntity(
        @Id Long id,
        String username,
        byte[] publicSigningKey,
        byte[] publicEncryptionKey,
        Instant registeredAt
) {

    public UserEntity(String username, byte[] publicSigningKey, byte[] publicEncryptionKey, Instant registeredAt) {
        this(null, username, publicSigningKey, publicEncryptionKey, registeredAt);
    }
}
