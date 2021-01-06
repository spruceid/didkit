package com.spruceid.didkitexample.config;

import com.spruceid.didkitexample.util.Resources;
import com.spruceid.didkitexample.websocket.SocketHandler;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

import java.util.concurrent.ConcurrentHashMap;

@Configuration
@EnableWebSocket
@AllArgsConstructor
public class WebSocketConfig implements WebSocketConfigurer {
    private final StringRedisTemplate redisTemplate;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry
                .addHandler(handler(), "/wss/verifiable-presentation-request")
                .setAllowedOrigins("https://" + Resources.baseUrl);
    }

    @Bean
    public ConcurrentHashMap<String, WebSocketSession> sessionMap() {
        return new ConcurrentHashMap<>();
    }

    @Bean
    public WebSocketHandler handler() {
        return new SocketHandler(redisTemplate, sessionMap());
    }
}