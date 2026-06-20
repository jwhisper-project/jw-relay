package io.github.artshp.jwhisper.relay.storage;

public record UserPublicKeys(
        byte[] signingKey,
        byte[] encryptionKey
) {
}
