package com.spruceid.java_jsp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class Options {
    private String proofPurpose;
    private String verificationMethod;
    private String challenge;
    private String domain;
}
