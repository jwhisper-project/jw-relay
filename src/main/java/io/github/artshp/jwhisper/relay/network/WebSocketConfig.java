package io.github.artshp.jwhisper.relay.network;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * Web socket configuration.
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    /**
     * JWhisper web socket handler.
     */
    private final RelayWebSocketHandler webSocketHandler;

    /**
     * Create a new instance of web socket config.
     * @param webSocketHandler JWhisper web socket handler
     */
    public WebSocketConfig(RelayWebSocketHandler webSocketHandler) {
        this.webSocketHandler = webSocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(webSocketHandler, "/whisper")
                .setAllowedOrigins("*");
    }
}
