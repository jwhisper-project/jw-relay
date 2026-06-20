package io.github.artshp.jwhisper.relay.storage;

/**
 * User's public keys.
 * @param signingKey encoded signing key
 * @param encryptionKey encoded encryption key
 */
public record UserPublicKeys(
        byte[] signingKey,
        byte[] encryptionKey
) {
}
