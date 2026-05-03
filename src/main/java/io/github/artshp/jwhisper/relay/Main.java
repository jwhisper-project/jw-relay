package io.github.artshp.jwhisper.relay;

import lombok.extern.slf4j.Slf4j;

/**
 * Relay app entry point.
 */
@Slf4j
class Main {

    /**
     * Relay app entry point.
     */
    static void main() {
        try {
            ServerApp app = new ServerApp();
            app.start();
        } catch (Exception e) {
            log.error("Unexpected error:", e);
        }
    }
}
