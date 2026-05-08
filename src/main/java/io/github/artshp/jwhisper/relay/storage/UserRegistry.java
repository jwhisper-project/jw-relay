package io.github.artshp.jwhisper.relay.storage;

import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class UserRegistry {

    /**
     * Map of usernames to their public keys
     */
    private final Map<String, PublicKey> users = new ConcurrentHashMap<>();

    public boolean isUsernameTaken(String username) {
        return users.containsKey(username.toLowerCase());
    }

    public void register(String username, PublicKey publicKey) {
        users.put(username.toLowerCase(), publicKey);
        log.info("User {} registered successfully", username);
    }
}
