package com.spruceid.didkitexample.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class DIDKitOptions {
    private String proofPurpose;
    private String verificationMethod;
    private String challenge;
    private String domain;
}
