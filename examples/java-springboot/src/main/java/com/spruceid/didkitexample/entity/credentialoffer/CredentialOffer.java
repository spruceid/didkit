package com.spruceid.didkitexample.entity.credentialoffer;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class CredentialOffer {
    final String type;
    final String expires;
    final CredentialPreview credentialPreview;
}
