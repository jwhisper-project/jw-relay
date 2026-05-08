package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.common.exception.InputRetryException;
import io.github.artshp.jwhisper.common.io.UserInputUtils;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;

/**
 * Server app class.
 */
@Slf4j
class ServerApp {

    private final ConfigManager configManager = new ConfigManager();

    /**
     * Constructs a new server application.
     */
    public ServerApp() {
    }

    /**
     * Start server application.
     */
    public void start() throws InputRetryException {
        log.info("Starting Relay Server");
        System.out.println("----- JWhisper Relay -----");

        char[] password = UserInputUtils.readPassword();
        KeyManagerFactory keyManagerFactory = IdentityManager.getKeyManagerFactory(password);

        ServerConfig config;
        if (!configManager.isConfigPresent()) {
            log.debug("No config present. Creating it...");

            int port = UserInputUtils.readPort();

            config = new ServerConfig(port);
            configManager.saveConfig(config);
        } else {
            log.debug("Config present. Loading it...");
            config = configManager.loadConfig();
        }

        try (NetworkServer server = new NetworkServer(keyManagerFactory, config.port())) {
            server.start();
        } catch (IOException e) {
            log.error("Failed to close network server.", e);
        }
    }
}
