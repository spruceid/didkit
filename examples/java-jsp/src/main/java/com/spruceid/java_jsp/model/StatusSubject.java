package com.spruceid.java_jsp.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Collections;
import java.util.HashMap;

@Getter
@Setter
public class StatusSubject extends Subject {
    private String status;

    public StatusSubject(String id, String status) {
        super(Collections.singletonMap("status", "https://schema.org/Text"), id);
        this.status = status;
    }
}
