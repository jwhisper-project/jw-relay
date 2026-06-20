package io.github.artshp.jwhisper.relay.exception;

/**
 * Exception for issues during registration.
 */
public class RegistrationException extends RuntimeException {

    /**
     * Constructs a new exception.
     * @see RuntimeException#RuntimeException()
     */
    public RegistrationException() {
        super();
    }

    /**
     * Constructs a new exception with the specified detail message.
     * @param message detail message
     * @see RuntimeException#RuntimeException(String)
     */
    public RegistrationException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     * @param message detail message
     * @param cause cause
     * @see RuntimeException#RuntimeException(String, Throwable)
     */
    public RegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause and a detail message of
     * {@code cause == null ? null : cause.toString())}.
     * @param cause cause
     * @see RuntimeException#RuntimeException(Throwable)
     */
    public RegistrationException(Throwable cause) {
        super(cause);
    }
}
