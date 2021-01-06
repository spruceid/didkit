package com.spruceid.didkitexample.auth;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class VPAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String FORM_USERNAME_KEY = "username";
    public static final String FORM_PASSWORD_KEY = "password";
    public static final String FORM_PRESENTATION_KEY = "presentation";
    public static final String FORM_TOKEN_KEY = "token";

    private final StringRedisTemplate redisTemplate;

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/sign-in", "POST");

    public VPAuthenticationFilter(AuthenticationManager authenticationManager, StringRedisTemplate redisTemplate) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        final String token = request.getParameter(FORM_TOKEN_KEY);

        if (token != null) {
            final String username = redisTemplate.opsForValue().get(token);

            if (username == null) {
                throw new AuthenticationServiceException("Invalid token!");
            }

            return new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
        }

        final String presentationRaw = request.getParameter(FORM_PRESENTATION_KEY);

        if (presentationRaw != null) {
            final ObjectMapper mapper = new ObjectMapper();
            final Map<String, Object> presentation = mapper.readValue(presentationRaw, new TypeReference<>() {
            });
            final VPAuthenticationToken authToken = new VPAuthenticationToken(presentation);
            return this.getAuthenticationManager().authenticate(authToken);
        }

        final String username = request.getParameter(FORM_USERNAME_KEY);
        final String password = request.getParameter(FORM_PASSWORD_KEY);
        final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return this.getAuthenticationManager().authenticate(authToken);
    }
}
