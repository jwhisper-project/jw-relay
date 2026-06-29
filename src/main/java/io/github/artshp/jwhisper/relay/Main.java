package io.github.artshp.jwhisper.relay;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;

/**
 * Relay app entry point.
 */
@Slf4j
final class Main {

    /**
     * Constructor to prohibit instantiating.
     */
    private Main() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Relay app entry point.
     * @param args CLI arguments
     */
    static void main(String[] args) {
        SpringApplication.run(RelayApplication.class, args);
    }
}
