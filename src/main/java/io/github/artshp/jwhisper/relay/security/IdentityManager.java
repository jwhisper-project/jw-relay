package io.github.artshp.jwhisper.relay.security;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

/**
 * Server identity manager. Responsible for server SSL certificate.
 */
@Slf4j
public final class IdentityManager {

    /**
     * Filename of key store with server certificate
     */
    private static final String KEYSTORE_FILE = "identity.p12";

    /**
     * Path to key store with server certificate
     */
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    /**
     * Does key store file exist?
     * @return {@code true} if key store file exists, otherwise {@code false}
     */
    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    /**
     * Get key manager factory with server certificate for SSL
     * @param password password to key store
     * @return key manager factory with server certificate for SSL
     * @throws WrongPasswordException if wrong password provided
     */
    public static KeyManagerFactory getKeyManagerFactory(char[] password) throws WrongPasswordException {
        KeyStore keyStore;
        if (isKeyStoreAvailable()) {
            LOGGER.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);
            keyStore = SecurityUtils.createAndLoadKeyStore(password, KEYSTORE_FILE_PATH);
        } else {
            throw new UnsupportedOperationException("Key Store is not available.");
        }

        KeyManagerFactory keyManagerFactory = SecurityUtils.newKeyManagerFactory();
        try {
            keyManagerFactory.init(keyStore, password);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            LOGGER.error("Failed to initialize key manager factory", e);
            throw new RuntimeException("Failed to initialize key manager factory", e);
        }

        return keyManagerFactory;
    }

    private IdentityManager() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
