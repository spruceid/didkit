package com.spruceid.didkitexample.controller;

import com.spruceid.DIDKit;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VersionController {

    @RequestMapping("/version")
    public String version() {
        return DIDKit.getVersion();
    }
}
