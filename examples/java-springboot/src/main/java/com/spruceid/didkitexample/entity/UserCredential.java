package com.spruceid.didkitexample.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
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

    @Getter
    @Setter
    @AllArgsConstructor
    public static class CredentialSubject {
        private String id;
        @JsonProperty("alumniOf")
        private String username;
    }

    private CredentialSubject credentialSubject;

    private static final TimeZone tz = TimeZone.getTimeZone("UTC");
    private static final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public UserCredential(String issuer, String subjectId, String subjectUsername) {
        context = new String[] {
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        };
        id = "urn:uuid:" + UUID.randomUUID();
        type = new String[]{"VerifiableCredential"};
        this.issuer = issuer;
        df.setTimeZone(tz);
        this.issuanceDate = df.format(new Date());
        this.credentialSubject = new CredentialSubject(subjectId, subjectUsername);
    }
}
