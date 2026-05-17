package io.github.artshp.jwhisper.relay.log;

import org.slf4j.MDC;

/**
 * Class responsible for logging context, e.g. setting values for variables (via {@code %X} marker).
 * @see MDC
 */
public final class LogContext {

    private static final String USERNAME = "username";
    private static final String SESSION_ID = "sessionId";

    private LogContext() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Set value for {@value USERNAME} logging context variable.
     * @param username username
     */
    public static void setUsername(String username) {
        MDC.put(USERNAME, username);
    }

    /**
     * Set value for {@value SESSION_ID} logging context variable.
     * @param sessionId session id
     */
    public static void setSessionNumber(String sessionId) {
        MDC.put(SESSION_ID, sessionId);
    }

    /**
     * Clear values for all logging context variables.
     */
    public static void clearContext() {
        MDC.clear();
    }
}
