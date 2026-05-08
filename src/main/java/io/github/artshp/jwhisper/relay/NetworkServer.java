package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.protocol.MessageTransport;
import io.github.artshp.jwhisper.common.protocol.RegisterRequest;
import io.github.artshp.jwhisper.common.protocol.StatusResponse;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class NetworkServer implements AutoCloseable {

    private final MessageTransport transport = new MessageTransport();
    private final ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();

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
                executorService.submit(new Servant((SSLSocket) serverSocket.accept(), transport));
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

    private static class Servant implements Runnable {

        private final SSLSocket socket;
        private final MessageTransport transport;

        public Servant(SSLSocket socket, MessageTransport transport) {
            this.socket = socket;
            this.transport = transport;
        }

        @Override
        public void run() {
            try (SSLSocket socket = this.socket) {
                log.info("Accepted connection from {}", socket.getInetAddress());

                WhisperMessage response = receive();
                try {
                    if (response instanceof RegisterRequest request) {
                        processRegisterRequest(request);
                    }

                    switch (response) {
                        case RegisterRequest request -> processRegisterRequest(request);
                        default -> throw new NetworkServiceException("Unexpected response: " + response);
                    }
                } catch (NetworkServiceException e) {
                    log.error("Failed to process request", e);
                }
            } catch (IOException e) {
                log.error("Error during communication with relay", e);
            }

            log.info("Closing connection from {}", socket.getInetAddress());
        }

        private void processRegisterRequest(RegisterRequest request) throws NetworkServiceException, IOException {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(request.publicKey());
            PublicKey publicKey;
            try {
                publicKey = SecurityUtils.KEY_FACTORY.generatePublic(keySpec);
            } catch (InvalidKeySpecException e) {
                throw new NetworkServiceException("Failed to generate public key.", e);
            }

            boolean valid = SigningUtils.verify(
                    publicKey,
                    request.username().getBytes(),
                    request.usernameSignature()
            );

            // TODO: replace with real logic
            if (!valid) {
                log.error("Failed to verify public key");
            } else {
                StatusResponse statusResponse = new StatusResponse(true, "Registered successfully");
                send(statusResponse);
            }
        }

        public void send(WhisperMessage message) throws IOException {
            transport.sendMessage(socket.getOutputStream(), message);
        }

        public WhisperMessage receive() throws IOException {
            return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
        }
    }
}
