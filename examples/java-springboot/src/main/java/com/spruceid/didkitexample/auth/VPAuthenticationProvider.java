package com.spruceid.didkitexample.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.didkitexample.entity.User;
import com.spruceid.didkitexample.user.UserService;
import com.spruceid.didkitexample.util.DIDKitOptions;
import lombok.AllArgsConstructor;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.util.List;
import java.util.Map;

@Component
@AllArgsConstructor
public class VPAuthenticationProvider implements AuthenticationProvider {
    private final UserService userService;

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        final VPAuthenticationToken token = (VPAuthenticationToken) auth;
        final Map<String, Object> presentation = token.getPresentation();

        final ObjectMapper mapper = new ObjectMapper();

        final Resource keyFile;
        final String key;

        try {
            keyFile = new FileSystemResource("./key.jwk");
            key = Files.readString(keyFile.getFile().toPath());
        } catch (Exception e) {
            throw new BadCredentialsException("Failed to load key.");
        } 

        try {
            final String holder = (String) presentation.get("holder");
            final String hash = holder.substring(8);
            final String verificationMethod = holder + "#" + hash;
            final DIDKitOptions options = new DIDKitOptions("authentication", verificationMethod, null, null);
            final String vpStr = mapper.writeValueAsString(presentation);
            final String optionsStr = mapper.writeValueAsString(options);

            final String result = DIDKit.verifyPresentation(vpStr, optionsStr);
            final Map<String, Object> resultMap = mapper.readValue(result, new TypeReference<>() {
            });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.out.println("[ERROR] VP: " + resultMap.get("errors"));
                throw new BadCredentialsException("Invalid presentation.");
            }
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid presentation.");
        }

        final Object vcs = presentation.get("verifiableCredential");
        final Map<String, Object> vc = (Map<String, Object>) (vcs instanceof Object[] ? ((Object[]) vcs)[0] : vcs);

        try {
            final String verificationMethod = DIDKit.keyToVerificationMethod("key", key);
            final DIDKitOptions options = new DIDKitOptions("assertionMethod", verificationMethod, null, null);
            final String vcStr = mapper.writeValueAsString(vc);
            final String optionsStr = mapper.writeValueAsString(options);
     
            final String result = DIDKit.verifyCredential(vcStr, optionsStr);
            final Map<String, Object> resultMap = mapper.readValue(result, new TypeReference<>() {
            });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.out.println("[ERROR] VC: " + resultMap.get("errors"));
                throw new BadCredentialsException("Invalid credential presented.");
            }
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid credential presented.");
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

