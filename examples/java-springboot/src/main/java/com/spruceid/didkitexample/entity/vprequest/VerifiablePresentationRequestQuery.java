package com.spruceid.didkitexample.entity.vprequest;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class VerifiablePresentationRequestQuery {
    private String type;
    private CredentialQuery credentialQuery;
}
