package com.spruceid.didkitexample;

import com.spruceid.didkitexample.util.KeyManagement;
import com.spruceid.didkitexample.util.Resources;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Paths;

@SpringBootApplication
public class DIDKitExampleApplication {

    public static void main(String[] args) throws Throwable {
        KeyManagement.createIfNotExists(Paths.get(Resources.key));
        SpringApplication.run(DIDKitExampleApplication.class, args);
    }
}
