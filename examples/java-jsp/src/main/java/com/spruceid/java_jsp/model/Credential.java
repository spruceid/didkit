package com.spruceid.java_jsp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Getter
@Setter
public class Credential {
    @JsonProperty("@context")
    private String[] context;

    private String id;

    private String[] type;

    private String issuer;

    private String issuanceDate;

    private String expirationDate;

    private Subject credentialSubject;

    private static final DateTimeFormatter dateFormat = DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.from(ZoneOffset.UTC));

    public Credential(String issuer, Subject subject) {
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

        this.credentialSubject = subject;
    }
}
