package io.github.artshp.jwhisper.relay.network;

import io.github.artshp.jwhisper.common.protocol.StatusResponse;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import io.github.artshp.jwhisper.relay.log.LogContext;
import io.github.artshp.jwhisper.relay.storage.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import tools.jackson.core.JacksonException;
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
        LogContext.setSessionNumber(session.getId());

        LOGGER.info("Session opened");

        LogContext.clearContext();
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws IOException {
        try {
            LogContext.setSessionNumber(session.getId());
            LOGGER.info("Received message");
            String payload = message.getPayload();

            WhisperMessage whisperMessage;
            try {
                whisperMessage = mapper.readValue(payload, WhisperMessage.class);
            } catch (JacksonException e) {
                LOGGER.error("Failed to parse received message: {}", payload);
                return;
            }

            // TODO: replace with real logic
            switch (whisperMessage) {
                default -> sendMessage(session, new StatusResponse(false, "Unknown whisper message"));
            }
        } finally {
            LogContext.clearContext();
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        LogContext.setSessionNumber(session.getId());

        activeSessions.values().remove(session);
        LOGGER.info("Session closed with status: {}", status);

        LogContext.clearContext();
    }

    private void sendMessage(WebSocketSession session, WhisperMessage whisperMessage) throws IOException {
        LOGGER.info("Sending message");
        session.sendMessage(new TextMessage(mapper.writeValueAsString(whisperMessage)));
    }
}
