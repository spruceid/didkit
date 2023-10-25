package com.spruceid.didkitexample.config;

import java.time.Duration;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.ConstructorBinding;

@Getter
@ConfigurationProperties(prefix = "didkit")
@ConfigurationPropertiesScan
public class DIDKitConfig {
    public Duration maxClockSkew;


    @ConstructorBinding
    DIDKitConfig(Duration maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }
}
