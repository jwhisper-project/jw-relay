package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.protocol.MessageTransport;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class NetworkServer implements AutoCloseable {

    private static final String TLS_PROTOCOL = "TLSv1.3";

    private final MessageTransport transport = new MessageTransport();
    private final ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();

    private final SSLServerSocketFactory serverSocketFactory;
    private final SSLServerSocket serverSocket;
    private final int port;

    private static SSLContext getSSLContext(KeyManagerFactory keyManagerFactory) {
        try {
            SSLContext sslContext = SSLContext.getInstance(TLS_PROTOCOL);
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

        public Servant(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (SSLSocket socket = this.socket) {
                log.info("Accepted connection from {}", socket.getInetAddress());
            } catch (IOException e) {
                log.error("Error during communication with relay", e);
            }

            log.info("Closing connection from {}", socket.getInetAddress());
        }
    }
}
