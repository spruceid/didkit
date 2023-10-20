package com.spruceid.didkitexample.controller;

import com.spruceid.DIDKit;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


@RestController
public class VersionController {
    private static Logger logger = LogManager.getLogger();

    @RequestMapping("/version")
    public String version() {
        logger.info("GET /version");
        return DIDKit.getVersion();
    }
}
