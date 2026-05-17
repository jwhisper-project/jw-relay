package io.github.artshp.jwhisper.relay.network;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.protocol.*;
import io.github.artshp.jwhisper.relay.log.LogContext;
import io.github.artshp.jwhisper.relay.storage.UserRegistry;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Relay server.
 */
@Slf4j
public class NetworkServer implements AutoCloseable {

    /**
     * Users registry/storage.
     */
    private final UserRegistry userRegistry = new UserRegistry();

    /**
     * Service responsible for network communication.
     */
    private final MessageTransport transport = new MessageTransport();

    /**
     * Executor service for network connections managing.
     */
    private final ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();

    /**
     * Map of sockets to their servants.
     */
    private final Map<Socket, Servant> users = new ConcurrentHashMap<>();

    /**
     * Server socket.
     */
    private final SSLServerSocket serverSocket;

    /**
     * Current client session id.
     */
    private BigInteger currentSessionId = BigInteger.ZERO;

    /**
     * Create SSL context for SSL server socket.
     * @param keyManagerFactory key manager factory with certificate for SSL
     * @return configured SSL context
     */
    private static SSLContext getSSLContext(KeyManagerFactory keyManagerFactory) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SecurityUtils.SSL_PROTOCOL);
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            LOGGER.error("Failed to initialize SSL context", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Create SSL server socket.
     * @param serverSocketFactory SSL server socket factory
     * @param port server port
     * @return configured SSL server socket
     */
    private SSLServerSocket getSSLServerSocket(SSLServerSocketFactory serverSocketFactory, int port) {
        try {
            return (SSLServerSocket) serverSocketFactory.createServerSocket(port);
        } catch (IOException e) {
            LOGGER.error("Failed to create server socket", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a new instance of network server.
     * @param keyManagerFactory key manager factory with certificate for SSL
     * @param port server port
     */
    public NetworkServer(KeyManagerFactory keyManagerFactory, int port) {
        this.serverSocket = getSSLServerSocket(
                getSSLContext(keyManagerFactory).getServerSocketFactory(),
                port
        );
    }

    /**
     * Start server.
     */
    public void start() {
        LOGGER.info("Starting Relay Server on {}:{}", serverSocket.getInetAddress(), serverSocket.getLocalPort());
        while (true) {
            try {
                currentSessionId = currentSessionId.add(BigInteger.ONE);
                executorService.submit(new Servant((SSLSocket) serverSocket.accept()));
            } catch (IOException e) {
                LOGGER.error("Failed to accept or close a connection", e);
            }
        }
    }

    /**
     * Stop server, close connections.
     * @throws IOException if an I/O error occurs when closing the server socket
     */
    @Override
    public void close() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    /**
     * Servant for incoming connection. One servant for one connection.
     */
    private class Servant implements Runnable {

        /**
         * Socket between relay and client.
         */
        private final SSLSocket socket;

        /**
         * Client session id. Based on {@link #currentSessionId} value.
         */
        private final String sessionId;

        /**
         * Lock for sending messages. It's needed for safety so many streams do not try
         * to send several messages simultaneously to one channel.
         * @see #send(WhisperMessage)
         */
        private final Object sendLock = new Object();

        /**
         * User's username. It's {@code null} before user is registered.
         */
        private String username = null;

        /**
         * Create a new servant for incoming connection.
         * @param socket client socket
         */
        public Servant(SSLSocket socket) {
            this.socket = socket;
            this.sessionId = currentSessionId.toString();
        }

        /**
         * Run servant, i.e. start serving connection.
         */
        @Override
        public void run() {
            LogContext.setSessionNumber(sessionId);
            try (SSLSocket socket = this.socket) {
                LOGGER.info("Accepted connection from {}", socket.getInetAddress());

                boolean isRunning = true;
                while (isRunning) {
                    WhisperMessage response = receive();
                    try {
                        switch (response) {
                            case RegisterRequest request -> processRegisterRequest(request);
                            case UserPublicKeyRequest request -> processUserPublicKeyRequest(request);
                            case EncryptedMessage message -> routeMessage(message);
                            case UnregisterRequest _ -> {
                                processUnregisterRequest();
                                isRunning = false;
                            }
                            default -> throw new NetworkServiceException("Unexpected response: " + response);
                        }
                    } catch (NetworkServiceException e) {
                        LOGGER.error("Failed to process request", e);
                    }
                }
            } catch (IOException e) {
                LOGGER.error("Error during communication with relay", e);
            }

            LOGGER.info("Closing connection from {}", socket.getInetAddress());
            LogContext.clearContext();
        }

        /**
         * Process incoming user register request.
         * @param request incoming request
         * @throws NetworkServiceException if failed to process request due to invalid request
         * @throws IOException if failed to send response
         */
        private void processRegisterRequest(RegisterRequest request) throws NetworkServiceException, IOException {
            PublicKey publicSigningKey;
            try {
                publicSigningKey = SecurityUtils.newSigningPublicKey(request.publicSigningKey());
            } catch (InvalidKeySpecException e) {
                throw new NetworkServiceException("Failed to generate public key.", e);
            }

            PublicKey publicEncryptionKey;
            try {
                publicEncryptionKey = SecurityUtils.newEncryptionPublicKey(request.publicEncryptionKey());
            } catch (InvalidKeySpecException e) {
                throw new NetworkServiceException("Failed to generate public key.", e);
            }

            username = request.username();
            boolean valid = SigningUtils.verify(
                    publicSigningKey,
                    username.getBytes(),
                    request.ownershipSignature()
            );

            if (!valid) {
                LOGGER.error("Failed to verify public key. Registration failed.");
                send(new StatusResponse(false, "Registration failed"));
            } else {
                if (userRegistry.isUsernameTaken(username)) {
                    send(new StatusResponse(false, "Username already taken"));
                } else {
                    LogContext.setUsername(username);
                    userRegistry.register(socket, username, publicSigningKey, publicEncryptionKey);
                    users.put(socket, this);
                    send(new StatusResponse(true, "Registered successfully"));
                }
            }
        }

        /**
         * Process incoming user public keys request.
         * @param request incoming request
         * @throws IOException if failed to send response
         */
        private void processUserPublicKeyRequest(UserPublicKeyRequest request) throws IOException {
            String username = request.targetUsername();
            LOGGER.info("Received user public key request of user {}", username);

            PublicKey publicSigningKey = userRegistry.getUserPublicSigningKey(username);
            if (publicSigningKey != null) {
                LOGGER.info("Successfully found public keys of user {}", username);
                PublicKey publicEncryptionKey = userRegistry.getUserPublicEncryptionKey(username);
                send(new UserPublicKeyResponse(
                        username, publicSigningKey.getEncoded(), publicEncryptionKey.getEncoded(), true
                ));
            } else {
                LOGGER.error("Failed to find public keys of user {}", username);
                send(new UserPublicKeyResponse(username, null, null, false));
            }
        }

        /**
         * Process and route incoming encrypted message.
         * @param encryptedMessage incoming message
         * @throws IOException if failed to send message to recipient
         */
        private void routeMessage(EncryptedMessage encryptedMessage) throws IOException {
            String recipient = encryptedMessage.recipient();
            LOGGER.info("Received encrypted message addressed to {}", recipient);

            Socket recipientSocket = userRegistry.getSocket(recipient);
            if (recipientSocket != null) {
                LOGGER.info("Sending message to {}", recipient);
                Servant recipientServant = users.get(recipientSocket);
                recipientServant.send(new UserPublicKeyResponse(
                        username,
                        userRegistry.getUserPublicSigningKey(username).getEncoded(),
                        userRegistry.getUserPublicEncryptionKey(username).getEncoded(),
                        true
                ));
                recipientServant.send(encryptedMessage);
                LOGGER.info("Sent message to {}", recipient);
            } else {
                LOGGER.error("Failed to send encrypted message to {}", recipient);
            }
        }

        /**
         * Process incoming user unregister request.
         * @throws IOException if failed to send response
         */
        private void processUnregisterRequest() throws IOException {
            if (userRegistry.unregister(socket)) {
                users.remove(socket);
                send(new StatusResponse(true, "Unregistered successfully"));
            } else {
                send(new StatusResponse(false, "Failed to unregister user"));
            }
        }

        /**
         * Send message to client.
         * <p>
         * This method is thread-safe.
         * @param message message to send
         * @throws IOException if failed to send message
         */
        @Synchronized("sendLock")
        private void send(WhisperMessage message) throws IOException {
            transport.sendMessage(socket.getOutputStream(), message);
        }

        /**
         * Receive message from client.
         * <p>
         * This method is <b>not</b> thread-safe.
         * @return received message
         * @throws IOException if failed to receive message
         */
        private WhisperMessage receive() throws IOException {
            return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
        }
    }
}
