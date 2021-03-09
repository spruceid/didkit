package com.spruceid.java_jsp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public abstract class Subject {
    @JsonProperty("@context")
    protected Map<String, String> context;

    protected String id;
}
