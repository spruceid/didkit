package com.spruceid.didkitexample.entity.credentialoffer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class CredentialPreview {
    @JsonProperty("@context")
    final List<String> context;

    final String id;
    final String type;
    final String issuer;
    final String issuanceDate;
    final String expirationDate;

    @JsonInclude
    final Map<String, Object> credentialSubject;
}
