package io.github.artshp.jwhisper.relay;

import lombok.extern.slf4j.Slf4j;

/**
 * Relay app entry point.
 */
@Slf4j
final class Main {

    private Main() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Relay app entry point.
     */
    static void main() {
        try {
            ServerApp app = new ServerApp();
            app.start();
        } catch (Exception e) {
            LOGGER.error("Unexpected error:", e);
        }
    }
}
