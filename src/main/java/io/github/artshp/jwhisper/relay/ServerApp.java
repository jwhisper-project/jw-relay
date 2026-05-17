package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.common.exception.InputRetryException;
import io.github.artshp.jwhisper.common.io.UserInputUtils;
import io.github.artshp.jwhisper.relay.config.ConfigManager;
import io.github.artshp.jwhisper.relay.config.ServerConfig;
import io.github.artshp.jwhisper.relay.network.NetworkServer;
import io.github.artshp.jwhisper.relay.security.IdentityManager;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;

/**
 * Server app class.
 */
@Slf4j
class ServerApp {

    /**
     * Config file manager.
     */
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
        LOGGER.info("Starting Relay Server");
        System.out.println("----- JWhisper Relay -----");

        char[] password = UserInputUtils.readPassword();
        KeyManagerFactory keyManagerFactory = IdentityManager.getKeyManagerFactory(password);

        ServerConfig config;
        if (!configManager.isConfigPresent()) {
            LOGGER.debug("No config present. Creating it...");

            int port = UserInputUtils.readPort();

            config = new ServerConfig(port);
            configManager.saveConfig(config);
        } else {
            LOGGER.debug("Config present. Loading it...");
            config = configManager.loadConfig();
        }

        try (NetworkServer server = new NetworkServer(keyManagerFactory, config.port())) {
            server.start();
        } catch (IOException e) {
            LOGGER.error("Failed to close network server.", e);
        }
    }
}
