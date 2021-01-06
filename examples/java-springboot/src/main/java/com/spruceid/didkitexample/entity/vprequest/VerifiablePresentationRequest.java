package com.spruceid.didkitexample.entity.vprequest;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class VerifiablePresentationRequest {
    private String type;
    private List<VerifiablePresentationRequestQuery> query;
    private String challenge;
    private String domain;
}
