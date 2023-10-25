package com.spruceid.didkitexample.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.NonNull;
import java.util.Optional;
import java.time.Instant;
import java.time.format.DateTimeFormatter;


@Getter
@Setter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class DIDKitOptions {
    private String proofPurpose;
    private String verificationMethod;
    private String challenge;
    private String domain;

    // This will be the "system time" for when something is processed
    // not the time the VP is created.
    private String created;

    public DIDKitOptions(
        String proofPurpose,
        String verificationMethod,
        @NonNull Optional<String> challenge,
        String domain,
        @NonNull Optional<Instant> created
    ) {
        this.proofPurpose = proofPurpose;
        this.verificationMethod = verificationMethod;
        this.challenge = challenge.orElse(null);
        this.domain = domain;
        this.created =
            created
            .map(i -> DateTimeFormatter.ISO_INSTANT.format(i))
            .orElse(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
    }
}
