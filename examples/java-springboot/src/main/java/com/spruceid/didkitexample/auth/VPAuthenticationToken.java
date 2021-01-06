package com.spruceid.didkitexample.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.didkitexample.entity.user.User;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Map;

@Getter
public class VPAuthenticationToken extends AbstractAuthenticationToken {
    private final Map<String, Object> presentation;
    private final User user;

    public VPAuthenticationToken(Map<String, Object> presentation) {
        super(null);

        this.presentation = presentation;
        this.user = null;

        setAuthenticated(false);
    }

    public VPAuthenticationToken(Map<String, Object> presentation, User user) {
        super(user.getAuthorities());

        this.presentation = presentation;
        this.user = user;

        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        try {
            return new ObjectMapper().writeValueAsString(presentation);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return "";
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
