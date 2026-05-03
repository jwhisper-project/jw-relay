package io.github.artshp.jwhisper.relay;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import java.io.Console;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

/**
 * Server app class.
 */
@Slf4j
class ServerApp {

    private final Console console;

    /**
     * Constructs a new server application.
     */
    public ServerApp() {
        console = System.console();
        if (console == null) {
            log.error("Console is not available.");
            throw new IllegalStateException("Console is not available.");
        }
    }

    /**
     * Start server application.
     */
    public void start() {
        log.info("Starting Relay Server");
        System.out.println("----- JWhisper Relay -----");

        Optional<char[]> password = readPassword(false);
        if (password.isEmpty()) {
            log.error("Failed to get password.");
            return;
        }

        KeyManagerFactory keyManagerFactory = IdentityManager.getKeyManagerFactory(password.get());

        try (NetworkServer server = new NetworkServer(keyManagerFactory, 8443)) {
            server.start();
        } catch (IOException e) {
            log.error("Failed to close network server.", e);
        }
    }

    private static boolean isPasswordValid(char[] password) {
        return password.length >= 4;
    }

    private Optional<char[]> readPassword(boolean repeat) {
        char[] password;

        boolean isValid;
        int i = 0;
        do {
            password = console.readPassword("Enter password: ");
            if (!isPasswordValid(password)) {
                isValid = false;
                log.warn("Password length should be at least 4. Try again.");
            } else {
                isValid = true;
            }

            i++;
        } while (!isValid && i < 3);

        if (!isValid) {
            log.error("Provided password is invalid.");
            return Optional.empty();
        }

        if (!repeat) {
            return Optional.of(password);
        }

        char[] passwordRetry;

        i = 0;
        do {
            passwordRetry = console.readPassword("Re-enter password: ");
            if (!Arrays.equals(password, passwordRetry)) {
                isValid = false;
                log.warn("Passwords are not equal. Try again.");
            } else {
                isValid = true;
            }

            i++;
        } while (!isValid && i < 3);

        if (!isValid) {
            log.warn("You failed to repeat the password.");
            return Optional.empty();
        }

        return Optional.of(password);
    }
}
