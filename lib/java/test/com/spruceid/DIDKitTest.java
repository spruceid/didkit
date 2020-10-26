package com.spruceid;

import com.spruceid.DIDKit;

class DIDKitTest {
    public static void main(String[] args) {
        String version = DIDKit.getVersion();
        System.out.println("Java libdidkit version: " + version);
    }
}
