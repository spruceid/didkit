package com.spruceid.didkitexample.websocket;

import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.concurrent.ConcurrentHashMap;

@Component
@AllArgsConstructor
public class SocketHandler extends TextWebSocketHandler {
    private final StringRedisTemplate redisTemplate;
    private final ConcurrentHashMap<String, WebSocketSession> sessionMap;

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        final String challenge = message.getPayload();
        final String sessionId = session.getId();
        sessionMap.put(challenge, session);
    }
}
