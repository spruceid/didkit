package com.spruceid.didkitexample.controller;

import com.spruceid.didkitexample.entity.user.User;
import com.spruceid.didkitexample.entity.vprequest.CredentialExample;
import com.spruceid.didkitexample.entity.vprequest.CredentialQuery;
import com.spruceid.didkitexample.entity.vprequest.VerifiablePresentationRequest;
import com.spruceid.didkitexample.entity.vprequest.VerifiablePresentationRequestQuery;
import com.spruceid.didkitexample.user.UserService;
import com.spruceid.didkitexample.util.Resources;
import com.spruceid.didkitexample.util.VerifiablePresentation;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@AllArgsConstructor
public class VerifiablePresentationRequestController {
    private final UserService userService;
    private final StringRedisTemplate redisTemplate;

    @Autowired
    private final ConcurrentHashMap<String, WebSocketSession> sessionMap;

    @GetMapping(value = "/verifiable-presentation-request/{challenge}", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerifiablePresentationRequest vpRequestGet(
            @PathVariable("challenge") String challenge
    ) {
        return new VerifiablePresentationRequest(
                "VerifiablePresentationRequest",
                Collections.singletonList(new VerifiablePresentationRequestQuery(
                        "QueryByExample",
                        new CredentialQuery(
                                "Sign in",
                                new CredentialExample(
                                        Collections.singletonList("https://www.w3.org/2018/credentials/v1"),
                                        "VerifiableCredential"
                                )
                        )
                )),
                challenge,
                Resources.baseUrl
        );
    }

    @PostMapping("/verifiable-presentation-request/{challenge}")
    @ResponseStatus(value = HttpStatus.NO_CONTENT)
    public void vpRequestPost(
            @PathVariable("challenge") String challenge,
            @RequestParam("presentation") String presentation
    ) throws Exception {
        final Resource keyFile;
        final String key;

        try {
            keyFile = new FileSystemResource(Resources.key);
            key = Files.readString(keyFile.getFile().toPath());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to load key");
        }

        final Map<String, Object> vc = VerifiablePresentation.verifyPresentation(key, presentation, challenge);
        final Map<String, Object> credentialSubject = (Map<String, Object>) vc.get("credentialSubject");

        final String username = credentialSubject.get("alumniOf").toString();
        final User user = (User) userService.loadUserByUsername(username);

        final String uuid = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(uuid, user.getUsername());
        redisTemplate.expire(uuid, Duration.ofSeconds(90));

        if (sessionMap.containsKey(challenge)) {
            try {
                sessionMap.get(challenge).sendMessage(new TextMessage(uuid));
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to return sign in token");
            }
            sessionMap.remove(challenge);
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token");
        }
    }
}
