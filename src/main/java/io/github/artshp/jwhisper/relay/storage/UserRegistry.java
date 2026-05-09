package io.github.artshp.jwhisper.relay.storage;

import lombok.extern.slf4j.Slf4j;

import java.net.Socket;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class UserRegistry {

    /**
     * Map of usernames to their public keys
     */
    private final Map<String, PublicKey> users = new ConcurrentHashMap<>();

    /**
     * Map of sockets to their usernames
     */
    private final Map<Socket, String> sockets = new ConcurrentHashMap<>();

    /**
     * Map of usernames to their sockets
     */
    private final Map<String, Socket> sockets2 = new ConcurrentHashMap<>();

    public boolean isUsernameTaken(String username) {
        return users.containsKey(username);
    }

    public void register(Socket socket, String username, PublicKey publicKey) {
        users.put(username, publicKey);
        sockets.put(socket, username);
        sockets2.put(username, socket);
        log.info("User {} registered successfully", username);
    }

    public PublicKey getUserPublicKey(String username) {
        return users.get(username);
    }

    public Socket getSocket(String username) {
        return sockets2.get(username);
    }

    public boolean unregister(Socket socket) {
        String username = sockets.get(socket);
        if (username != null) {
            users.remove(username);
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
