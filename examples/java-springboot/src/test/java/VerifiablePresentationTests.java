import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.spruceid.didkitexample.util.VerifiablePresentation;
import com.spruceid.didkitexample.util.DIDKitOptions;

import java.util.Optional;

import java.time.Instant;
import java.time.Duration;

class VerifiablePresenationTests {
    public static String validKey() {
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"2dmpl0ZBbTA2X501O8XbDf2maPkKluXaZfI6pSuBPJg\",\"d\":\"dR6sD1Coca1lttJt1KceJa9XuPMEx4mR8DZ174WGffg\"}";
    }

    public static String validPresentation() {
        return "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"id\":\"urn:uuid:5905fb5a-238d-4677-b925-b7c422b62650\",\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\"],\"id\":\"urn:uuid:9f12872b-6d31-4b74-97bf-337c839e0ba4\",\"type\":[\"VerifiableCredential\"],\"credentialSubject\":{\"id\":\"did:tz:tz1c6HxLrqR2cmm554qZ16jM1noBT242FoDg\",\"alumniOf\":\"charles\"},\"issuer\":\"did:key:z6Mku7f1yjNfra5q1FFFFQuUgmNCB337CBYAEhWKqDkSeECF\",\"issuanceDate\":\"2023-10-04T16:22:49.558339114Z\",\"proof\":{\"type\":\"Ed25519Signature2018\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:key:z6Mku7f1yjNfra5q1FFFFQuUgmNCB337CBYAEhWKqDkSeECF#z6Mku7f1yjNfra5q1FFFFQuUgmNCB337CBYAEhWKqDkSeECF\",\"created\":\"2023-10-04T21:22:49.561Z\",\"jws\":\"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..iieKtJ0Pp8f4CnwiQI3clmX6E_WCHnP6TOrJUQ4Irjf4I5ewmgtWCuAFwPwiJj12CNdkGFRB-DHMfnI08H0EAA\"},\"expirationDate\":\"2024-04-04T16:22:49.558339114Z\"},\"proof\":{\"@context\":{\"Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021\":{\"@context\":{\"@protected\":true,\"@version\":1.1,\"challenge\":\"https://w3id.org/security#challenge\",\"created\":{\"@id\":\"http://purl.org/dc/terms/created\",\"@type\":\"http://www.w3.org/2001/XMLSchema#dateTime\"},\"domain\":\"https://w3id.org/security#domain\",\"expires\":{\"@id\":\"https://w3id.org/security#expiration\",\"@type\":\"http://www.w3.org/2001/XMLSchema#dateTime\"},\"id\":\"@id\",\"jws\":\"https://w3id.org/security#jws\",\"nonce\":\"https://w3id.org/security#nonce\",\"proofPurpose\":{\"@context\":{\"@protected\":true,\"@version\":1.1,\"assertionMethod\":{\"@container\":\"@set\",\"@id\":\"https://w3id.org/security#assertionMethod\",\"@type\":\"@id\"},\"authentication\":{\"@container\":\"@set\",\"@id\":\"https://w3id.org/security#authenticationMethod\",\"@type\":\"@id\"},\"id\":\"@id\",\"type\":\"@type\"},\"@id\":\"https://w3id.org/security#proofPurpose\",\"@type\":\"@vocab\"},\"publicKeyJwk\":{\"@id\":\"https://w3id.org/security#publicKeyJwk\",\"@type\":\"@json\"},\"type\":\"@type\",\"verificationMethod\":{\"@id\":\"https://w3id.org/security#verificationMethod\",\"@type\":\"@id\"}},\"@id\":\"https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021\"},\"Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021\":{\"@id\":\"https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021\"},\"P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021\":{\"@context\":{\"@protected\":true,\"@version\":1.1,\"challenge\":\"https://w3id.org/security#challenge\",\"created\":{\"@id\":\"http://purl.org/dc/terms/created\",\"@type\":\"http://www.w3.org/2001/XMLSchema#dateTime\"},\"domain\":\"https://w3id.org/security#domain\",\"expires\":{\"@id\":\"https://w3id.org/security#expiration\",\"@type\":\"http://www.w3.org/2001/XMLSchema#dateTime\"},\"id\":\"@id\",\"jws\":\"https://w3id.org/security#jws\",\"nonce\":\"https://w3id.org/security#nonce\",\"proofPurpose\":{\"@context\":{\"@protected\":true,\"@version\":1.1,\"assertionMethod\":{\"@container\":\"@set\",\"@id\":\"https://w3id.org/security#assertionMethod\",\"@type\":\"@id\"},\"authentication\":{\"@container\":\"@set\",\"@id\":\"https://w3id.org/security#authenticationMethod\",\"@type\":\"@id\"},\"id\":\"@id\",\"type\":\"@type\"},\"@id\":\"https://w3id.org/security#proofPurpose\",\"@type\":\"@vocab\"},\"publicKeyJwk\":{\"@id\":\"https://w3id.org/security#publicKeyJwk\",\"@type\":\"@json\"},\"type\":\"@type\",\"verificationMethod\":{\"@id\":\"https://w3id.org/security#verificationMethod\",\"@type\":\"@id\"}},\"@id\":\"https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021\"},\"P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021\":{\"@id\":\"https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021\"}},\"type\":\"Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021\",\"proofPurpose\":\"authentication\",\"challenge\":\"c031a95f-2a23-460b-bd42-39544ab19030\",\"verificationMethod\":\"did:tz:tz1c6HxLrqR2cmm554qZ16jM1noBT242FoDg#blockchainAccountId\",\"created\":\"2023-10-23T20:22:59.251Z\",\"domain\":\"open-actually-wahoo.ngrok-free.app\",\"jws\":\"eyJhbGciOiJFZEJsYWtlMmIiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..AOqTVGtFlHXfHCUT6ua68G__s5LBkjeBK5jGxQGvTVXNvEZqxzBBExeeGG5EXC2CVqS1wkO8ucEMQpcej3KQCg\",\"publicKeyJwk\":{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"E993DJyLL2QEcWmmYIA6TuxOZqI9wEMywu67JF5xYjA\"}},\"holder\":\"did:tz:tz1c6HxLrqR2cmm554qZ16jM1noBT242FoDg\"}";
    }

    public static String validChallenge() {
        return "c031a95f-2a23-460b-bd42-39544ab19030";
    }

    public static Instant presentationCreatedAt() {
        return Instant.parse("2023-10-23T20:22:59.251Z");
    }

    public static Instant credentialCreatedAt() {
        return Instant.parse("2023-10-04T21:22:49.561Z");
    }

    @Test
    void verifyPresentationAllEmptyString() throws Exception {
        final var key = "";
        final var presentation = "";
        final var challenge = "";

        assertThrows(
            com.fasterxml.jackson.databind.exc.MismatchedInputException.class,
            () -> {
                VerifiablePresentation
                .verifyPresentation(
                    key,
                    presentation,
                    Optional.of(challenge),
                    Optional.empty(),
                    Optional.empty()
                );
            }
        );
    }

    @Test
    void verifyPresentationGoodPresentation() throws Exception {
        // key, presentation, and challenge will need to be updated about once
        // a year until we get test code up to generate VPs for us.
        final var key = validKey();
        final var presentation = validPresentation();
        final var challenge = validChallenge();

        VerifiablePresentation
        .verifyPresentation(
            key,
            presentation,
            Optional.of(challenge),
            Optional.empty(),
            Optional.empty()
        );
    }

    @Test
    void verifyPresentationPresentationWithinMaxClockSkew() throws Exception {
        // key, presentation, and challenge will need to be updated about once
        // a year until we get test code up to generate VPs for us.
        final var key = validKey();
        final var presentation = validPresentation();
        final var challenge = validChallenge();
        final var maxClockSkew = Duration.ofSeconds(5);
        final var processAtTime =
            presentationCreatedAt().plus(Duration.ofSeconds(4));

        VerifiablePresentation
        .verifyPresentation(
            key,
            presentation,
            Optional.of(challenge),
            Optional.of(processAtTime),
            Optional.of(maxClockSkew)
        );
    }


    @Test
    void verifyPresentationCreatedInFuture() throws Exception {
        // key, presentation, and challenge will need to be updated about once
        // a year until we get test code up to generate VPs for us.
        final var key = validKey();
        final var presentation = validPresentation();
        final var challenge = validChallenge();

        //We process the presentation in the past to simulate a presentation
        //created in the future
        final Instant pastTime =
            Instant
            .now()
            .minus(Duration.ofDays(10));


        assertThrows(
            org.springframework.web.server.ResponseStatusException.class,
            () -> {
            VerifiablePresentation
            .verifyPresentation(
                key,
                presentation,
                Optional.of(challenge),
                Optional.of(pastTime),
                Optional.empty()
            );
            }
        );
    }

    @Test
    void verifyPresentationCreated() throws Exception {
        final var expectedCreated = presentationCreatedAt();

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());

        final var actualCreated =
            VerifiablePresentation.getPresentationCreated(presentationMap);

        assertTrue(actualCreated.compareTo(expectedCreated) == 0);
    }

    @Test
    void verifyCredentialCreated() throws Exception {
        final var expectedCreated = credentialCreatedAt();

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());

        final var actualCreated =
            VerifiablePresentation.getCredentialCreated(presentationMap);

        assertTrue(actualCreated.compareTo(expectedCreated) == 0);
    }


    @Test
    void verifyCreatedTimesGood() throws Exception {
        final Duration maxClockSkew = Duration.ofSeconds(5);
        // now is set to 1 min after the presentation created date
        final Instant now = presentationCreatedAt().plus(Duration.ofMinutes(1));

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());


        VerifiablePresentation.validateCreatedTimes(
           now,
           maxClockSkew,
           presentationMap
        );
    }

    @Test
    void verifyCreatedTimesPresentationInFutureLessThanSkew() throws Exception {
        final Duration maxClockSkew = Duration.ofSeconds(5);
        // now is set to 4 sec before the presentation created date
        final Instant now = presentationCreatedAt().minus(Duration.ofSeconds(4));

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());


        VerifiablePresentation.validateCreatedTimes(
           now,
           maxClockSkew,
           presentationMap
        );
    }

    @Test
    void verifyCreatedPresentationInFuture() throws Exception {
        final Duration maxClockSkew = Duration.ofSeconds(5);
        // now is set to 4 min before the presentation created date
        final Instant now = presentationCreatedAt().minus(Duration.ofMinutes(4));

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());

        assertThrows(
            org.springframework.web.server.ResponseStatusException.class,
            () -> {
                VerifiablePresentation.validateCreatedTimes(
                    now,
                    maxClockSkew,
                    presentationMap
                );
            }
        );
    }


    @Test
    void verifyCreatedCredentialInFuture() throws Exception {
        final Duration maxClockSkew = Duration.ofSeconds(5);
        // now is set to 4 min before the presentation created date
        final Instant now = credentialCreatedAt().minus(Duration.ofMinutes(4));

        final var presentationMap =
            VerifiablePresentation.presentationToMap(validPresentation());

        assertThrows(
            org.springframework.web.server.ResponseStatusException.class,
            () -> {
                VerifiablePresentation.validateCreatedTimes(
                    now,
                    maxClockSkew,
                    presentationMap
                );
            }
        );
    }


}
