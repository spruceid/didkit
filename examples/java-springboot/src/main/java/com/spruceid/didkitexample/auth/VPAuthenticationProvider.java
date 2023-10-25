package com.spruceid.didkitexample.auth;

import com.spruceid.didkitexample.entity.user.User;
import com.spruceid.didkitexample.user.UserService;
import com.spruceid.didkitexample.util.Resources;
import com.spruceid.didkitexample.util.VerifiablePresentation;
import lombok.AllArgsConstructor;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;


import com.spruceid.didkitexample.config.DIDKitConfig;

import java.util.Optional;
import java.util.Map;

import java.nio.file.Files;


@Component
@AllArgsConstructor
public class VPAuthenticationProvider implements AuthenticationProvider {
    private final UserService userService;

    @Autowired
    private final DIDKitConfig didkitConfig;


    @Override
    public Authentication authenticate(Authentication auth) {
        final VPAuthenticationToken token = (VPAuthenticationToken) auth;
        final Map<String, Object> presentation = token.getPresentation();

        final Resource keyFile;
        final String key;

        try {
            keyFile = new FileSystemResource(Resources.key);
            key = Files.readString(keyFile.getFile().toPath());
        } catch (Exception e) {
            throw new BadCredentialsException("Failed to load key");
        }

        final Map<String, Object> vc;
        try {
            vc = VerifiablePresentation.verifyPresentation(
                     key,
                     presentation,
                     Optional.empty(),
                     Optional.empty(),
                     Optional.of(didkitConfig.maxClockSkew)
                 );
        } catch (Exception e) {
            throw new BadCredentialsException("Failed to verify presentation");
        }

        final Map<String, Object> credentialSubject = (Map<String, Object>) vc.get("credentialSubject");

        final String username = credentialSubject.get("alumniOf").toString();
        final User user = (User) userService.loadUserByUsername(username);

        return new VPAuthenticationToken(token.getPresentation(), user);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return VPAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
