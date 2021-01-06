package com.spruceid.didkitexample.util;

import com.spruceid.DIDKit;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class KeyManagement {
    public static void createIfNotExists(Path file) throws Exception {
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
}
