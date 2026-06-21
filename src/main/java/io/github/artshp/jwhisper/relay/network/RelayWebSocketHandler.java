package io.github.artshp.jwhisper.relay.network;

import io.github.artshp.jwhisper.relay.storage.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class RelayWebSocketHandler extends TextWebSocketHandler {

    private final ObjectMapper mapper = new ObjectMapper();
    private final UserRepository userRepository;

    private final Map<String, WebSocketSession> activeSessions = new ConcurrentHashMap<>();

    public RelayWebSocketHandler(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        LOGGER.info("Low-level TCP channel upgraded to WebSocket. Session ID: {}", session.getId());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws IOException {
        LOGGER.info("Received message {}", message.getPayload());
        session.sendMessage(message); // TODO: replace with real business logic
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        activeSessions.values().remove(session);
        LOGGER.info("Session dropped. Session ID: {}, Close status: {}", session.getId(), status);
    }
}
