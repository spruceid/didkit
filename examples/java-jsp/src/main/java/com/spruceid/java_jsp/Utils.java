package com.spruceid.java_jsp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.java_jsp.model.Credential;
import com.spruceid.java_jsp.model.Options;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class Utils {
    public static void createKeyIfNotExists(Path file) throws Exception {
        if (Files.notExists(file)) {
            final String key = DIDKit.generateEd25519Key();
            final List<String> lines = Collections.singletonList(key);

            try {
                Files.write(file, lines, StandardCharsets.UTF_8);
            } catch (Exception e) {
                System.out.println("Failed to generate a key file.");
                System.err.println(e.getMessage());
                throw e;
            }

            System.out.println("Key file was successfully generated.");
        } else {
            System.out.println("Key file is already present, skipping generation.");
        }
    }

    public static String loadKey(Path file) throws Exception {
        return String.join("", Files.readAllLines(file));
    }

    public static String issueCredential(Credential credential, Options options, String key) throws Exception {
        final ObjectMapper mapper = new ObjectMapper();
        final String credentialStr = mapper.writeValueAsString(credential);
        final String optionsStr = mapper.writeValueAsString(options);

        return DIDKit.issueCredential(credentialStr, optionsStr, key);
    }
}
