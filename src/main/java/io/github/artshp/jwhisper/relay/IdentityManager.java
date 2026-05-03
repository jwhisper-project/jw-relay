package io.github.artshp.jwhisper.relay;

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

@Slf4j
class IdentityManager {

    private static final String KEYSTORE_FILE = "identity.p12";
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    public static KeyManagerFactory getKeyManagerFactory(char[] password) throws WrongPasswordException {
        KeyStore keyStore;
        if (isKeyStoreAvailable()) {
            log.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);
            keyStore = SecurityUtils.createAndLoadKeyStore(password, KEYSTORE_FILE_PATH);
        } else {
            // TODO: finish implementation
            throw new UnsupportedOperationException("Key Store is not available.");
        }

        KeyManagerFactory keyManagerFactory = SecurityUtils.newKeyManagerFactory();
        try {
            keyManagerFactory.init(keyStore, password);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            log.error("Failed to initialize key manager factory", e);
            throw new RuntimeException("Failed to initialize key manager factory", e);
        }

        return keyManagerFactory;
    }
}
