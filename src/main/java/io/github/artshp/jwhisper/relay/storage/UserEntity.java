package io.github.artshp.jwhisper.relay.storage;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("USERS")
public record UserEntity(
        @Id String username,
        byte[] publicSigningKey,
        byte[] publicEncryptionKey,
        Instant registeredAt
) {
}
