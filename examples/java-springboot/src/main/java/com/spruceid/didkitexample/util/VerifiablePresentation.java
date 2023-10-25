package com.spruceid.didkitexample.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.didkitexample.config.DIDKitConfig;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.AbstractList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import java.time.Instant;
import java.time.Duration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import lombok.NonNull;

public class VerifiablePresentation {
    private static Logger logger = LogManager.getLogger();

    public static Map<String, Object> verifyPresentation(
            @NonNull final String key,
            @NonNull final String presentation,
            @NonNull final Optional<String> challenge,
            @NonNull final Optional<Instant> processAtTime,
            @NonNull final Optional<Duration> maxClockSkew
    ) throws Exception {
        logger.info("Converting String VP into Map<String, Object>");
        logger.info("VP: " + presentation);

        final Map<String, Object> presentationMap =
            presentationToMap(presentation);

        return VerifiablePresentation
            .verifyPresentation(
                key,
                presentationMap,
                challenge,
                processAtTime,
                maxClockSkew
            );
    }

    public static Map<String, Object> verifyPresentation(
            @NonNull final String key,
            @NonNull final Map<String, Object> presentation,
            @NonNull final Optional<String> challenge,
            @NonNull final Optional<Instant> processAtTime,
            @NonNull final Optional<Duration> maxClockSkew
    ) throws Exception {
        logger.info("Attempting to verify Map presentation");

        final Duration maxSkewOrZero = maxClockSkew.orElse(Duration.ofSeconds(0));
        final ObjectMapper mapper = new ObjectMapper();


        validateCreatedTimes(processAtTime.orElse(Instant.now()), maxSkewOrZero, presentation);

        // Verify the Presentation
        try {
            final var vpOptions =
                new DIDKitOptions(
                        "authentication",  // proofPurpose
                        null,              // verificationMethos
                        challenge,         // challenge
                        Resources.baseUrl, // domain
                        processAtTime.map(i -> i.plus(maxSkewOrZero)) // created
                    );

            final String vpStr = mapper.writeValueAsString(presentation);
            final String vpOptionsStr = mapper.writeValueAsString(vpOptions);

            logger.info("vpStr: " + vpStr);
            logger.info("vpOptionsStr: " + vpOptionsStr);


            final String result = DIDKit.verifyPresentation(vpStr, vpOptionsStr);
            logger.info("DIDKit.verifyPresentation result: " + result);
            final Map<String, Object> resultMap =
                mapper.readValue(result, new TypeReference<>() { });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                logger.error("VP: " + resultMap.get("errors"));
                throw new ResponseStatusException(
                              HttpStatus.BAD_REQUEST,
                              "Invalid presentation"
                          );
            }
        } catch (Exception e) {
            logger.error("Failed to verify presentation: " + e.toString());
            throw new ResponseStatusException(
                          HttpStatus.INTERNAL_SERVER_ERROR,
                          "Failed to verify presentation"
                      );
        }

        //Select the first vc if we have multiple in the presentation
        final Object vcs = presentation.get("verifiableCredential");
        logger.info("vcs type: " + vcs.getClass());
        final Map<String, Object> vc = getFirstVc(vcs);

        // Verify the Credential
        try {
            final var vcOptions =
                new DIDKitOptions(
                        "assertionMethod", // proofPurpose
                        null,              // verificationMethod
                        Optional.empty(),  // challenge
                        null,              // domain
                        processAtTime.map(i -> i.plus(maxSkewOrZero)) // created
                    );
            final String vcStr = mapper.writeValueAsString(vc);
            final String vcOptionsStr = mapper.writeValueAsString(vcOptions);

            logger.info("vcStr: " + vcStr);
            logger.info("vcOptionsStr: " + vcOptionsStr);

            final String result = DIDKit.verifyCredential(vcStr, vcOptionsStr);
            logger.info("DIDKit.verifyCredential result: " + result);
            final Map<String, Object> resultMap = mapper.readValue(result, new TypeReference<>() {
            });

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                logger.error("VC: " + resultMap.get("errors"));
                throw new ResponseStatusException(
                              HttpStatus.BAD_REQUEST,
                              "Invalid credential"
                          );
            }
        } catch (Exception e) {
            logger.error("Exception validating credential: " + e);
            throw new ResponseStatusException(
                          HttpStatus.INTERNAL_SERVER_ERROR,
                          "Failed to verify credential"
                      );
        }

        return vc;
    }


    public static void validateCreatedTimes(
        @NonNull final Instant now,
        @NonNull final Duration maxClockSkew,
        @NonNull final Map<String, Object> presentation
    ) throws Exception {
        final Instant credentialCreated = getCredentialCreated(presentation);
        final Instant presentationCreated = getPresentationCreated(presentation);
        final Instant nowWithSkew = now.plus(maxClockSkew);

        if(credentialCreated.compareTo(nowWithSkew) > 0) {
            logger.error("The Credential in the presentation is not yet valid");
            logger.error("credentialCreated: " + credentialCreated);
            logger.error("processedAt:       " + nowWithSkew);
            throw new ResponseStatusException(
                          HttpStatus.BAD_REQUEST,
                          "Credential in presentation is not yet valid"
                      );
        }

        if(presentationCreated.compareTo(nowWithSkew) > 0) {
            logger.error("The presentation is not yet valid");
            logger.error("presentationCreated: " + presentationCreated);
            logger.error("processedAt:         " + nowWithSkew);
            throw new ResponseStatusException(
                          HttpStatus.BAD_REQUEST,
                          "Presentation is not yet valid"
                      );
        }
    }

    public static Instant getCredentialCreated(
        @NonNull final Map<String, Object> presentation
    ) {
        final Object vcs = presentation.get("verifiableCredential");
        final Map<String, Object> vc = getFirstVc(vcs);
        final Map<String, Object> proof = (Map<String, Object>)vc.get("proof");
        final String createdStr = (String)proof.get("created");
        final Instant created = Instant.parse(createdStr);
        return created;
    }

    public static Instant getPresentationCreated(
        @NonNull final Map<String, Object> presentation
    ) {
        final Map<String, Object> proof = (Map<String, Object>)presentation.get("proof");
        final String createdStr = (String)proof.get("created");
        final Instant created = Instant.parse(createdStr);
        return created;
    }

    public static Map<String, Object> presentationToMap(
        @NonNull String presentation
    ) throws Exception {
        final ObjectMapper mapper = new ObjectMapper();

        final Map<String, Object> presentationMap =
            mapper.readValue(presentation, new TypeReference<>() {});

        return presentationMap;
    }

    private static Map<String, Object> getFirstVc(Object vcs) {
        if(vcs instanceof Object[]) {
            Object r = ((Object[]) vcs)[0];
            logger.info("r type: " + r.getClass());
            return (Map<String, Object>) r;
        }
        else if(vcs instanceof AbstractList) {
            Object r = ((AbstractList) vcs).get(0);
            logger.info("r type: " + r.getClass());
            return (Map<String, Object>) r;
        }
        else {
            logger.info("vc type: " + vcs.getClass());
            return (Map<String, Object>) vcs;
        }
    }
}
