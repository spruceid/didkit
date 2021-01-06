package com.spruceid.didkitexample.entity.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

@Getter
@Setter
public class UserCredential {
    @JsonProperty("@context")
    private String[] context;

    private String id;

    private String[] type;

    private String issuer;

    private String issuanceDate;

    private String expirationDate;

    @Getter
    @Setter
    @AllArgsConstructor
    public static class CredentialSubject {
        private String id;
        @JsonProperty("alumniOf")
        private String username;
    }

    private CredentialSubject credentialSubject;

    private static final DateTimeFormatter dateFormat = DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.from(ZoneOffset.UTC));

    public UserCredential(String issuer, String subjectId, String subjectUsername) {
        this.context = new String[]{
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
        };

        this.id = "urn:uuid:" + UUID.randomUUID();
        this.type = new String[]{"VerifiableCredential"};
        this.issuer = issuer;

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime exp = now.plus(Period.ofMonths(6));
        this.issuanceDate = dateFormat.format(now.toInstant(ZoneOffset.UTC));
        this.expirationDate = dateFormat.format(exp.toInstant(ZoneOffset.UTC));

        this.credentialSubject = new CredentialSubject(subjectId, subjectUsername);
    }
}
