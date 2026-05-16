package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.protocol.*;
import io.github.artshp.jwhisper.relay.storage.UserRegistry;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class NetworkServer implements AutoCloseable {

    private final UserRegistry userRegistry = new UserRegistry();
    private final MessageTransport transport = new MessageTransport();
    private final ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();
    private final Map<Socket, Servant> users = new ConcurrentHashMap<>();

    private final SSLServerSocketFactory serverSocketFactory;
    private final SSLServerSocket serverSocket;
    private final int port;

    private static SSLContext getSSLContext(KeyManagerFactory keyManagerFactory) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SecurityUtils.SSL_PROTOCOL);
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            log.error("Failed to initialize SSL context", e);
            throw new RuntimeException(e);
        }
    }

    private SSLServerSocket getSSLServerSocket() {
        try {
            return (SSLServerSocket) serverSocketFactory.createServerSocket(port);
        } catch (IOException e) {
            log.error("Failed to create server socket", e);
            throw new RuntimeException(e);
        }
    }

    public NetworkServer(KeyManagerFactory keyManagerFactory, int port) {
        this.port = port;
        this.serverSocketFactory = getSSLContext(keyManagerFactory).getServerSocketFactory();
        this.serverSocket = getSSLServerSocket();
    }

    public void start() {
        log.info("Starting Relay Server on {}:{}", serverSocket.getInetAddress(), serverSocket.getLocalPort());
        while (true) {
            try {
                executorService.submit(new Servant((SSLSocket) serverSocket.accept()));
            } catch (IOException e) {
                log.error("Failed to accept or close a connection", e);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    private class Servant implements Runnable {

        private final SSLSocket socket;
        private final Object sendLock = new Object();
        private final Object receiveLock = new Object();

        private String username = null;

        public Servant(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (SSLSocket socket = this.socket) {
                log.info("Accepted connection from {}", socket.getInetAddress());

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
                        log.error("Failed to process request", e);
                    }
                }
            } catch (IOException e) {
                log.error("Error during communication with relay", e);
            }

            LogContext.clearContext();
            log.info("Closing connection from {}", socket.getInetAddress());
        }

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
                log.error("Failed to verify public key. Registration failed.");
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

        private void processUserPublicKeyRequest(UserPublicKeyRequest request) throws IOException {
            String username = request.targetUsername();
            log.info("Received user public key request of user {}", username);

            PublicKey publicSigningKey = userRegistry.getUserPublicSigningKey(username);
            if (publicSigningKey != null) {
                log.info("Successfully found public keys of user {}", username);
                PublicKey publicEncryptionKey = userRegistry.getUserPublicEncryptionKey(username);
                send(new UserPublicKeyResponse(
                        username, publicSigningKey.getEncoded(), publicEncryptionKey.getEncoded(), true
                ));
            } else {
                log.error("Failed to find public keys of user {}", username);
                send(new UserPublicKeyResponse(username, null, null, false));
            }
        }

        private void routeMessage(EncryptedMessage encryptedMessage) throws IOException {
            String recipient = encryptedMessage.recipient();
            log.info("Received encrypted message addressed to {}", recipient);

            Socket recipientSocket = userRegistry.getSocket(recipient);
            if (recipientSocket != null) {
                log.info("Sending message to {}", recipient);
                Servant recipientServant = users.get(recipientSocket);
                recipientServant.send(new UserPublicKeyResponse(
                        username,
                        userRegistry.getUserPublicSigningKey(username).getEncoded(),
                        userRegistry.getUserPublicEncryptionKey(username).getEncoded(),
                        true
                ));
                recipientServant.send(encryptedMessage);
                log.info("Sent message to {}", recipient);
            } else {
                log.error("Failed to send encrypted message to {}", recipient);
            }
        }

        private void processUnregisterRequest() throws IOException {
            if (userRegistry.unregister(socket)) {
                users.remove(socket);
                send(new StatusResponse(true, "Unregistered successfully"));
            } else {
                send(new StatusResponse(false, "Failed to unregister user"));
            }
        }

        public void send(WhisperMessage message) throws IOException {
            synchronized (sendLock) {
                transport.sendMessage(socket.getOutputStream(), message);
            }
        }

        public WhisperMessage receive() throws IOException {
            synchronized (receiveLock) {
                return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
            }
        }
    }
}
