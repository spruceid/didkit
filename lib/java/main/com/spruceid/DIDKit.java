package com.spruceid;

public class DIDKit {
    public static native String getVersion();

    static {
        System.loadLibrary("didkit");
    }
}
