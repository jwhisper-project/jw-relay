package io.github.artshp.jwhisper.relay.storage;

import lombok.extern.slf4j.Slf4j;

import java.net.Socket;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class UserRegistry {

    /**
     * Map of usernames to their public signing keys
     */
    private final Map<String, PublicKey> userPublicSigningKeys = new ConcurrentHashMap<>();

    /**
     * Map of usernames to their public encryption keys
     */
    private final Map<String, PublicKey> userPublicEncryptionKeys = new ConcurrentHashMap<>();

    /**
     * Map of sockets to their usernames
     */
    private final Map<Socket, String> sockets = new ConcurrentHashMap<>();

    /**
     * Map of usernames to their sockets
     */
    private final Map<String, Socket> sockets2 = new ConcurrentHashMap<>();

    public boolean isUsernameTaken(String username) {
        return userPublicSigningKeys.containsKey(username);
    }

    public void register(Socket socket, String username, PublicKey publicSigningKey, PublicKey publicEncryptionKey) {
        userPublicSigningKeys.put(username, publicSigningKey);
        userPublicEncryptionKeys.put(username, publicEncryptionKey);
        sockets.put(socket, username);
        sockets2.put(username, socket);
        log.info("User {} registered successfully", username);
    }

    public PublicKey getUserPublicSigningKey(String username) {
        return userPublicSigningKeys.get(username);
    }

    public PublicKey getUserPublicEncryptionKey(String username) {
        return userPublicEncryptionKeys.get(username);
    }

    public Socket getSocket(String username) {
        return sockets2.get(username);
    }

    public boolean unregister(Socket socket) {
        String username = sockets.get(socket);
        if (username != null) {
            userPublicSigningKeys.remove(username);
            userPublicEncryptionKeys.remove(username);
            sockets.remove(socket);
            sockets2.remove(username);
            log.info("User {} unregistered successfully", username);
            return true;
        } else {
            log.error("User could not be unregistered");
            return false;
        }
    }
}
