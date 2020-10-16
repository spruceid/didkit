package com.spruceid;

public class DIDKit {
    public static native String getVersion();

    static {
        System.loadLibrary("didkit");
    }

    public static void main(String[] args) {
        String version = DIDKit.getVersion();
        System.out.println("Java libdidkit version: " + version);
    }
}
