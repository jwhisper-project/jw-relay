package io.github.artshp.jwhisper.relay.storage;

import io.github.artshp.jwhisper.common.crypto.PublicKeyUtils;
import io.github.artshp.jwhisper.relay.exception.LoginException;
import io.github.artshp.jwhisper.relay.exception.RegistrationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketSession;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Users registry. Manages currently registered and logged-in users.
 */
@Component
@Slf4j
public class UserRegistry {

    /**
     * Users database repository.
     */
    private final UserRepository repository;

    /**
     * Map of sessions to their usernames.
     */
    private final Map<WebSocketSession, String> sessions = new ConcurrentHashMap<>();

    /**
     * Map of usernames to their sessions.
     */
    private final Map<String, WebSocketSession> sessionsReverse = new ConcurrentHashMap<>();

    /**
     * Create a new user registry.
     * @param repository users repository
     */
    public UserRegistry(UserRepository repository) {
        this.repository = repository;
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
     * @param username user's username
     * @param publicSigningKey user's public signing key
     * @param publicEncryptionKey user's public encryption key
     * @throws RegistrationException if error occurred during persistence to database.
     */
    public void register(String username, PublicKey publicSigningKey, PublicKey publicEncryptionKey) {
        try {
            repository.save(new UserEntity(
                    username,
                    PublicKeyUtils.toRawBytes(publicSigningKey),
                    PublicKeyUtils.toRawBytes(publicEncryptionKey),
                    Instant.now())
            );
        } catch (Exception e) {
            LOGGER.error("Failed to register user", e);
            throw new RegistrationException("Failed to register user", e);
        }

        LOGGER.info("User {} registered successfully", username);
    }

    /**
     * Log in user.
     * @param session client session
     * @param username user's username
     * @throws LoginException if username doesn't exist or user is already logged in.
     */
    public void login(WebSocketSession session, String username) {
        if (!repository.existsByUsername(username)) {
            throw new LoginException("Username %s not found".formatted(username));
        }

        if (sessionsReverse.containsKey(username)) {
            throw new LoginException("User %s is already logged in".formatted(username));
        }

        sessions.put(session, username);
        sessionsReverse.put(username, session);
        LOGGER.info("User {} logged in successfully", username);
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
     * Get client's session.
     * @param username target user username
     * @return session to target user if logged-in, otherwise {@code null}
     */
    public WebSocketSession getSession(String username) {
        return sessionsReverse.get(username);
    }

    /**
     * Get client's username.
     * @param session session
     * @return username if logged-in, otherwise {@code null}
     */
    public String getUsername(WebSocketSession session) {
        return sessions.get(session);
    }

    /**
     * Is client logged in?
     * @param session session
     * @return {@code true} if user is logged-in, otherwise {@code false}
     */
    public boolean isLoggedIn(WebSocketSession session) {
        return sessions.containsKey(session);
    }

    /**
     * Is client logged in?
     * @param username username
     * @return {@code true} if user is logged-in, otherwise {@code false}
     */
    public boolean isLoggedIn(String username) {
        return sessionsReverse.containsKey(username);
    }

    /**
     * Log out user.
     * @param session session
     * @return {@code true} if logged user out successfully, otherwise {@code false}
     */
    public boolean logout(WebSocketSession session) {
        String username = sessions.get(session);
        if (username != null) {
            sessions.remove(session);
            sessionsReverse.remove(username);
            LOGGER.info("User {} logged out successfully", username);
            return true;
        } else {
            LOGGER.error("User could not be logged out");
            return false;
        }
    }
}
