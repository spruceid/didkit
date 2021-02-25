package com.spruceid;

import com.spruceid.DIDKitException;

public class DIDKit {
    public static native String getVersion();
    public static native String generateEd25519Key() throws DIDKitException;
    public static native String keyToDID(String methodName, String jwk) throws DIDKitException;
    public static native String keyToVerificationMethod(String methodName, String jwk) throws DIDKitException;
    public static native String issueCredential(String credential, String linkedDataProofOptions, String key) throws DIDKitException;
    public static native String verifyCredential(String verifiableCredential, String linkedDataProofOptions);
    public static native String issuePresentation(String presentation, String linkedDataProofOptions, String key) throws DIDKitException;
    public static native String DIDAuth(String holder, String linkedDataProofOptions, String key) throws DIDKitException;
    public static native String verifyPresentation(String verifiablePresentation, String linkedDataProofOptions);
    public static native String resolveDID(String did, String inputMetadata);
    public static native String dereferenceDIDURL(String didUrl, String inputMetadata);

    static {
        System.loadLibrary("didkit");
    }
}
