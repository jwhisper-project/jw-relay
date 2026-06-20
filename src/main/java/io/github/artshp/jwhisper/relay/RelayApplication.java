package io.github.artshp.jwhisper.relay;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

@SpringBootApplication
@EnableJdbcRepositories(basePackages = "io.github.artshp.jwhisper.relay.storage")
public class RelayApplication {
}
