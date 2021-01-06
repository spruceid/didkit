package com.spruceid.didkitexample.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.didkitexample.entity.credentialoffer.CredentialOffer;
import com.spruceid.didkitexample.entity.credentialoffer.CredentialPreview;
import com.spruceid.didkitexample.entity.user.User;
import com.spruceid.didkitexample.user.UserService;
import com.spruceid.didkitexample.util.Resources;
import lombok.AllArgsConstructor;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@AllArgsConstructor
public class CredentialOfferController {
    private final UserService userService;
    private final StringRedisTemplate redisTemplate;

    private static final DateTimeFormatter dateFormat = DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.from(ZoneOffset.UTC));

    @GetMapping(value = "/credential-offer/{token}", produces = MediaType.APPLICATION_JSON_VALUE)
    public CredentialOffer credentialOfferGet(
            @PathVariable("token") String token
    ) {
        final Resource keyFile;
        final String key;
        final String issuer;

        try {
            keyFile = new FileSystemResource(Resources.key);
            key = Files.readString(keyFile.getFile().toPath());
            issuer = DIDKit.keyToDID("key", key);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to load key.");
        }

        final String username = redisTemplate.opsForValue().get(token);

        if (username == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token");
        }

        final UUID uuid = UUID.randomUUID();
        final String id = "urn:uuid:" + uuid;

        final LocalDateTime nowLocal = LocalDateTime.now(ZoneId.systemDefault());
        final LocalDateTime expiresLocal = nowLocal.plus(Duration.ofMinutes(15));
        final LocalDateTime expirationLocal = nowLocal.plus(Period.ofMonths(6));

        final Instant nowInstant = nowLocal.toInstant(ZoneOffset.UTC);
        final Instant expiresInstant = expiresLocal.toInstant(ZoneOffset.UTC);
        final Instant expirationInstant = expirationLocal.toInstant(ZoneOffset.UTC);

        final String issuance = dateFormat.format(nowInstant);
        final String expires = dateFormat.format(expiresInstant);
        final String expiration = dateFormat.format(expirationInstant);

        return new CredentialOffer(
                "CredentialOffer",
                expires,
                new CredentialPreview(
                        List.of(
                                "https://www.w3.org/2018/credentials/v1",
                                "https://schema.org/"
                        ),
                        id,
                        "VerifiableCredential",
                        issuer,
                        issuance,
                        expiration,
                        Collections.singletonMap("alumniOf", username)
                )
        );
    }

    @PostMapping(value = "/credential-offer/{token}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> credentialOfferPost(
            @PathVariable("token") String token,
            @RequestParam("subject_id") String did
    ) throws Exception {
        final String username = redisTemplate.opsForValue().get(token);
        final User user = (User) userService.loadUserByUsername(username);

        final String vc = userService.issueCredential(did, user);
        final ObjectMapper mapper = new ObjectMapper();
        final Map<String, Object> vcMap = mapper.readValue(vc, new TypeReference<>() {
        });

        return vcMap;
    }
}
