package io.github.artshp.jwhisper.relay.log;

import org.slf4j.MDC;

public class LogContext {

    public static void setUsername(String username) {
        MDC.put("username", username);
    }

    public static void clearContext() {
        MDC.clear();
    }
}
