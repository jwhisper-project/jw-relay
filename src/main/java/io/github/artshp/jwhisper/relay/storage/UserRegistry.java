package io.github.artshp.jwhisper.relay.storage;

import io.github.artshp.jwhisper.relay.util.SpringContextBridge;
import lombok.extern.slf4j.Slf4j;

import java.net.Socket;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Users registry. Manages currently registered (logged in) users.
 */
@Slf4j
public class UserRegistry {

    /**
     * Users database repository.
     */
    private final UserRepository repository = SpringContextBridge.getBean(UserRepository.class);

    /**
     * Map of sockets to their usernames.
     */
    private final Map<Socket, String> sockets = new ConcurrentHashMap<>();

    /**
     * Map of usernames to their sockets.
     */
    private final Map<String, Socket> socketsReverse = new ConcurrentHashMap<>();

    /**
     * Create a new user registry.
     */
    public UserRegistry() {
    }

    /**
     * Is given username taken, i.e. is there any registered user with the same username?
     * @param username username to check
     * @return {@code true} if username is taken, otherwise {@code false}
     */
    public boolean isUsernameTaken(String username) {
        return repository.existsByUsername(username);
    }

    /**
     * Register user.
     * @param socket client socket.
     * @param username user's username
     * @param publicSigningKey user's public signing key
     * @param publicEncryptionKey user's public encryption key
     */
    public void register(Socket socket, String username, PublicKey publicSigningKey, PublicKey publicEncryptionKey) {
        repository.save(new UserEntity(
                username,
                publicSigningKey.getEncoded(),
                publicEncryptionKey.getEncoded(),
                Instant.now())
        );

        sockets.put(socket, username);
        socketsReverse.put(username, socket);
        LOGGER.info("User {} registered successfully", username);
    }

    /**
     * Get user's public keys set (signing + encryption).
     * @param username target user username
     * @return public keys of target user if registered, otherwise {@link Optional#empty()}
     */
    public Optional<UserPublicKeys> getUserPublicKeys(String username) {
        return repository.findByUsername(username)
                .map(user -> new UserPublicKeys(
                        user.publicSigningKey(),
                        user.publicEncryptionKey()
                ));
    }

    /**
     * Get client's socket.
     * @param username target user username
     * @return socket to target user if registered, otherwise {@code null}
     */
    public Socket getSocket(String username) {
        return socketsReverse.get(username);
    }

    /**
     * Unregister user.
     * @param socket client socket.
     * @return {@code true} if unregistered user successfully, otherwise {@code false}
     */
    public boolean unregister(Socket socket) {
        String username = sockets.get(socket);
        if (username != null) {
            sockets.remove(socket);
            socketsReverse.remove(username);
            LOGGER.info("User {} unregistered successfully", username);
            return true;
        } else {
            LOGGER.error("User could not be unregistered");
            return false;
        }
    }
}
