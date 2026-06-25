package io.github.artshp.jwhisper.relay.network;

import io.github.artshp.jwhisper.common.crypto.PublicKeyUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.protocol.*;
import io.github.artshp.jwhisper.relay.exception.LoginException;
import io.github.artshp.jwhisper.relay.exception.RegistrationException;
import io.github.artshp.jwhisper.relay.log.LogContext;
import io.github.artshp.jwhisper.relay.storage.UserPublicKeys;
import io.github.artshp.jwhisper.relay.storage.UserRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

/**
 * JWhisper web socket handler, i.e. server.
 * Handles communication with clients.
 */
@Component
@Slf4j
public class RelayWebSocketHandler extends TextWebSocketHandler {

    /**
     * Object mapper for JSONs.
     */
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * User registry.
     */
    private final UserRegistry userRegistry;

    /**
     * Create a new relay web socket handler.
     * @param userRegistry user registry
     */
    public RelayWebSocketHandler(UserRegistry userRegistry) {
        this.userRegistry = userRegistry;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        LogContext.setSessionNumber(session.getId());

        LOGGER.info("Session opened");

        LogContext.clearContext();
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        LogContext.setSessionNumber(session.getId());

        if (userRegistry.isLoggedIn(session)) {
            userRegistry.logout(session);
        }
        LOGGER.info("Session closed with status: {}", status);

        LogContext.clearContext();
    }

    /**
     * Handle incoming message from client. Send response if necessary.
     * @param session client session
     * @param message incoming message
     * @throws IOException if failed to send response
     */
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws IOException {
        try {
            LogContext.setSessionNumber(session.getId());
            LOGGER.info("Received message");
            String payload = message.getPayload();

            WhisperMessage whisperMessage;
            try {
                whisperMessage = mapper.readValue(payload, WhisperMessage.class);
            } catch (JacksonException e) {
                LOGGER.error("Failed to parse received message: {}", payload);
                return;
            }

            try {
                switch (whisperMessage) {
                    case RegisterRequest request -> processRegisterRequest(session, request);
                    case LoginRequest request -> processLoginRequest(session, request);
                    case UserPublicKeyRequest request -> processUserPublicKeyRequest(session, request);
                    case EncryptedMessage encryptedMessage -> routeMessage(session, encryptedMessage);
                    case LogoutRequest request -> processLogoutRequest(session, request);
                    default -> sendMessage(session, new StatusResponse(false, "Unknown whisper message"));
                }
            } catch (NetworkServiceException e) {
                LOGGER.error("Failed to process request", e);
            }
        } finally {
            LogContext.clearContext();
        }
    }

    /**
     * Process incoming user register request.
     * @param session session
     * @param request incoming request
     * @throws NetworkServiceException if failed to process request due to invalid request
     * @throws IOException if failed to send response
     */
    private void processRegisterRequest(WebSocketSession session, RegisterRequest request) throws NetworkServiceException, IOException {
        PublicKey publicSigningKey;
        try {
            publicSigningKey = PublicKeyUtils.newSigningPublicKey(request.publicSigningKey());
        } catch (InvalidKeySpecException e) {
            throw new NetworkServiceException("Failed to generate public key.", e);
        }

        PublicKey publicEncryptionKey;
        try {
            publicEncryptionKey = PublicKeyUtils.newEncryptionPublicKey(request.publicEncryptionKey());
        } catch (InvalidKeySpecException e) {
            throw new NetworkServiceException("Failed to generate public key.", e);
        }

        String username = request.username();
        boolean valid = SigningUtils.verify(
                publicSigningKey,
                username.getBytes(),
                request.ownershipSignature()
        );

        String responseId = request.id();
        if (!valid) {
            LOGGER.error("Failed to verify public key. Registration failed.");
            sendMessage(session, new StatusResponse(responseId, false, "Registration failed"));
        } else {
            if (userRegistry.isUsernameTaken(username)) {
                sendMessage(session, new StatusResponse(responseId, false, "Username already taken"));
            } else {
                try {
                    userRegistry.register(username, publicSigningKey, publicEncryptionKey);
                    sendMessage(session, new StatusResponse(responseId, true, "Registered successfully"));
                } catch (RegistrationException e) {
                    LOGGER.error("Registration failed", e);
                    sendMessage(session, new StatusResponse(responseId, false, "Registration failed due to: %s".formatted(e.getMessage())));
                }
            }
        }
    }

    /**
     * Process incoming user login request.
     * @param session session
     * @param request incoming request
     * @throws NetworkServiceException if failed to process request due to invalid request
     * @throws IOException if failed to send response
     */
    private void processLoginRequest(WebSocketSession session, LoginRequest request) throws NetworkServiceException, IOException {
        Optional<UserPublicKeys> publicKeysOptional = userRegistry.getUserPublicKeys(request.username());
        if (publicKeysOptional.isEmpty()) {
            LOGGER.error("User {} does not exist.", request.username());
            throw new NetworkServiceException("User does not exist.");
        }

        UserPublicKeys publicKeys = publicKeysOptional.get();
        PublicKey publicSigningKey;
        try {
            publicSigningKey = PublicKeyUtils.newSigningPublicKey(publicKeys.signingKey());
        } catch (InvalidKeySpecException e) {
            throw new NetworkServiceException("Failed to generate public key.", e);
        }

        String username = request.username();
        boolean valid = SigningUtils.verify(
                publicSigningKey,
                username.getBytes(),
                request.ownershipSignature()
        );

        String responseId = request.id();
        if (!valid) {
            LOGGER.error("Failed to verify public key. Login failed.");
            sendMessage(session, new StatusResponse(responseId, false, "Login failed"));
        } else {
            try {
                userRegistry.login(session, username);
                LogContext.setUsername(username);
                sendMessage(session, new StatusResponse(responseId, true, "Logged in successfully"));
            } catch (LoginException e) {
                LOGGER.error("Login failed", e);
                sendMessage(session, new StatusResponse(responseId, false, "Login failed due to: %s".formatted(e.getMessage())));
            }
        }
    }

    /**
     * Process incoming user public keys request.
     * @param session session
     * @param request incoming request
     * @throws IOException if failed to send response
     * @throws NetworkServiceException if user is not logged-in
     */
    private void processUserPublicKeyRequest(WebSocketSession session, UserPublicKeyRequest request) throws IOException, NetworkServiceException {
        checkUserIsLoggedIn(session);

        String username = request.targetUsername();
        LOGGER.info("Received user public key request of user {}", username);

        String responseId = request.id();
        Optional<UserPublicKeys> publicKeysOptional = userRegistry.getUserPublicKeys(username);
        if (publicKeysOptional.isPresent()) {
            LOGGER.info("Successfully found public keys of user {}", username);
            UserPublicKeys publicKeys = publicKeysOptional.get();
            sendMessage(session, new UserPublicKeyResponse(
                    responseId, username, publicKeys.signingKey(), publicKeys.encryptionKey(), true
            ));
        } else {
            LOGGER.error("Failed to find public keys of user {}", username);
            sendMessage(session, new UserPublicKeyResponse(
                    responseId, username, null, null, false
            ));
        }
    }

    /**
     * Process and route incoming encrypted message.
     * @param session session
     * @param encryptedMessage incoming message
     * @throws IOException if failed to send message to recipient
     * @throws NetworkServiceException if user is not logged-in
     */
    private void routeMessage(WebSocketSession session, EncryptedMessage encryptedMessage) throws IOException, NetworkServiceException {
        String username = checkUserIsLoggedIn(session);

        String recipient = encryptedMessage.recipient();
        LOGGER.info("Received encrypted message addressed to {}", recipient);

        if (userRegistry.isLoggedIn(session)) {
            LOGGER.info("Sending message to {}", recipient);
            WebSocketSession recipientSession = userRegistry.getSession(username);

            Optional<UserPublicKeys> publicKeysOptional = userRegistry.getUserPublicKeys(username);
            if (publicKeysOptional.isPresent()) {
                UserPublicKeys publicKeys = publicKeysOptional.get();
                sendMessage(recipientSession, new UserPublicKeyResponse(
                        username,
                        publicKeys.signingKey(),
                        publicKeys.encryptionKey(),
                        true
                ));
                sendMessage(recipientSession, encryptedMessage);
                LOGGER.info("Sent message to {}", recipient);
            } else {
                LOGGER.error("Failed to get public keys of {}", username);
            }
        } else {
            LOGGER.error("Failed to send encrypted message to {}", recipient);
        }
    }

    /**
     * Process incoming user unregister request.
     * @param session session
     * @param request incoming request
     * @throws IOException if failed to send response
     * @throws NetworkServiceException if user is not logged-in
     */
    private void processLogoutRequest(WebSocketSession session, LogoutRequest request) throws IOException, NetworkServiceException {
        checkUserIsLoggedIn(session);

        String responseId = request.id();
        if (userRegistry.logout(session)) {
            sendMessage(session, new StatusResponse(responseId, true, "Logged out successfully"));
            session.close(CloseStatus.NORMAL);
        } else {
            sendMessage(session, new StatusResponse(responseId, false, "Failed to log user out"));
        }
    }

    /**
     * Check if user is logged-in. If yes, set corresponding logging context and return username.
     * @param session session
     * @return username of user if it's logged-in
     * @throws NetworkServiceException if user is not logged-in
     */
    private String checkUserIsLoggedIn(WebSocketSession session) throws NetworkServiceException {
        if (!userRegistry.isLoggedIn(session)) {
            throw new NetworkServiceException("User is not logged-in.");
        }

        String username = userRegistry.getUsername(session);
        LogContext.setUsername(username);

        return username;
    }

    /**
     * Send message/response to client.
     * @param session client session
     * @param whisperMessage message to be sent
     * @throws IOException if failed to send request
     */
    private void sendMessage(WebSocketSession session, WhisperMessage whisperMessage) throws IOException {
        LOGGER.info("Sending message");
        session.sendMessage(new TextMessage(mapper.writeValueAsString(whisperMessage)));
    }
}
