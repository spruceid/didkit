package com.spruceid.didkitexample.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

public class VerifiablePresentation {
    public static Map<String, Object> verifyPresentation(
            final String key,
            final String presentation,
            final String challenge
    ) throws Exception {
        final ObjectMapper mapper = new ObjectMapper();

        final Map<String, Object> presentationMap = mapper.readValue(presentation, new TypeReference<>() {
        });

        return VerifiablePresentation.verifyPresentation(key, presentationMap, challenge);
    }

    public static Map<String, Object> verifyPresentation(
            final String key,
            final Map<String, Object> presentation,
            final String challenge
    ) {
        final ObjectMapper mapper = new ObjectMapper();

        try {
            final DIDKitOptions options = new DIDKitOptions(
                    "authentication",
                    null,
                    challenge,
                    Resources.baseUrl
            );
            final String vpStr = mapper.writeValueAsString(presentation);
            final String optionsStr = mapper.writeValueAsString(options);

            final String result = DIDKit.verifyPresentation(vpStr, optionsStr);
            final Map<String, Object> resultMap = mapper.readValue(result, new TypeReference<>() {
            });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.out.println("[ERROR] VP: " + resultMap.get("errors"));
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid presentation");
            }
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to verify presentation");
        }

        final Object vcs = presentation.get("verifiableCredential");
        final Map<String, Object> vc = (Map<String, Object>) (vcs instanceof Object[] ? ((Object[]) vcs)[0] : vcs);

        try {
            final DIDKitOptions options = new DIDKitOptions(
                    "assertionMethod",
                    null,
                    null,
                    null
            );
            final String vcStr = mapper.writeValueAsString(vc);
            final String optionsStr = mapper.writeValueAsString(options);

            final String result = DIDKit.verifyCredential(vcStr, optionsStr);
            final Map<String, Object> resultMap = mapper.readValue(result, new TypeReference<>() {
            });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.out.println("[ERROR] VC: " + resultMap.get("errors"));
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential");
            }
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to verify credential");
        }

        return vc;
    }
}
