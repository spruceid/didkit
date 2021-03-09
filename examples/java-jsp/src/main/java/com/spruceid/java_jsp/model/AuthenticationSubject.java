package com.spruceid.java_jsp.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Collections;

@Getter
@Setter
public class AuthenticationSubject extends Subject {
    private String username;

    public AuthenticationSubject(String id, String username) {
        super(Collections.singletonMap("username", "https://schema.org/Text"), id);
        this.username = username;
    }
}
