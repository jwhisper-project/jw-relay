package io.github.artshp.jwhisper.relay;

import io.github.artshp.jwhisper.common.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Optional;

@Slf4j
class IdentityManager {

    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String KEYSTORE_FILE = "identity.p12";
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    private static KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance(KEY_STORE_TYPE);
        } catch (KeyStoreException e) {
            log.error("Key Store type {} is not supported.", KEY_STORE_TYPE, e);
            throw new IllegalStateException("Key Store type is not supported.", e);
        }
    }

    private static KeyManagerFactory getKeyManagerFactory() {
        try {
            return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            log.error("Key Manager Factory algorithm {} is not supported.", KEY_STORE_TYPE, e);
            throw new IllegalStateException("Key Manager Factory algorithm is not supported.", e);
        }
    }

    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    public static KeyManagerFactory getKeyManagerFactory(char[] password) throws WrongPasswordException {
        KeyStore keyStore = getKeyStore();

        if (isKeyStoreAvailable()) {
            log.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);

            try (InputStream fis = Files.newInputStream(KEYSTORE_FILE_PATH)) {
                keyStore.load(fis, password);
            } catch (NoSuchAlgorithmException | CertificateException e) {
                log.error("Failed to load key store from file \"{}\"", KEYSTORE_FILE_PATH, e);
                throw new RuntimeException("Failed to load key store from file \"" + KEYSTORE_FILE_PATH + "\"", e);
            } catch (IOException e) {
                Class<?> causeClass = Optional.ofNullable(e.getCause())
                        .map(Throwable::getClass)
                        .orElse(null);

                // Was it caused by wrong password?
                if (UnrecoverableKeyException.class.equals(causeClass)) {
                    throw new WrongPasswordException("Wrong password provided for key store", e);
                } else {
                    throw new RuntimeException("Failed to load key store from file \"" + KEYSTORE_FILE_PATH + "\"", e);
                }
            }
        } else {
            // TODO: finish implementation
            throw new UnsupportedOperationException("Key Store is not available.");
        }

        KeyManagerFactory keyManagerFactory = getKeyManagerFactory();
        try {
            keyManagerFactory.init(keyStore, password);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            log.error("Failed to initialize key manager factory", e);
            throw new RuntimeException("Failed to initialize key manager factory", e);
        }

        return keyManagerFactory;
    }
}
