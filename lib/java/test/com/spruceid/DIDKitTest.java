package com.spruceid;

import com.spruceid.DIDKit;

class DIDKitTest {
    public static void main(String[] args) throws DIDKitException {
        String version = DIDKit.getVersion();

        // Generate key
        String jwk = DIDKit.generateEd25519Key();

        // Convert key to DID
        String did = DIDKit.keyToDID("key", jwk);

        // Get verificationMethod for DID
        String verificationMethod = DIDKit.keyToVerificationMethod("key", jwk);

        // Trigger Exception
        boolean threw = false;
        try {
            DIDKit.keyToDID("key", "{}");
        } catch (DIDKitException e) {
            threw = true;
        }
        assert threw;

        // Issue Credential
        String credential = "{"
            + "   \"@context\": \"https://www.w3.org/2018/credentials/v1\","
            + "   \"id\": \"http://example.org/credentials/3731\","
            + "   \"type\": [\"VerifiableCredential\"],"
            + "   \"issuer\": \"" + did + "\","
            + "   \"issuanceDate\": \"2020-08-19T21:41:50Z\","
            + "   \"credentialSubject\": {"
            + "       \"id\": \"did:example:d23dd687a7dc6787646f2eb98d0\""
            + "   }"
            + "}";
        String vcOptions = "{"
            + "  \"proofPurpose\": \"assertionMethod\","
            + "  \"verificationMethod\": \"" + verificationMethod + "\""
            + "}";
        String vc = DIDKit.issueCredential(credential, vcOptions, jwk);

        // Verify Credential
        String vcVerifyOptions = "{"
            + "  \"proofPurpose\": \"assertionMethod\""
            + "}";
        String vcResult = DIDKit.verifyCredential(vc, vcVerifyOptions);
        assert vcResult.contains("\"errors\":[]");

        // Issue Presentation
        String presentation = "{"
            + "   \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],"
            + "   \"id\": \"http://example.org/presentations/3731\","
            + "   \"type\": [\"VerifiablePresentation\"],"
            + "   \"holder\": \"" + did + "\","
            + "   \"verifiableCredential\": " + vc
            + "}";
        String vpOptions = "{"
            + "  \"proofPurpose\": \"authentication\","
            + "  \"verificationMethod\": \"" + verificationMethod + "\""
            + "}";
        String vp = DIDKit.issuePresentation(presentation, vpOptions, jwk);

        // Verify Presentation
        String vpVerifyOptions = "{"
            + "  \"proofPurpose\": \"authentication\""
            + "}";
        String vpResult = DIDKit.verifyPresentation(vp, vpVerifyOptions);
        assert vpResult.contains("\"errors\":[]");

        // Resolve DID
        String resolutionResult = DIDKit.resolveDID(did, "{}");
        assert resolutionResult.contains("\"didDocument\":{");

        // Dereference DID URL
        String dereferencingResult = DIDKit.dereferenceDIDURL(verificationMethod, "{}");
        assert dereferencingResult.startsWith("[{");

        // Create a DIDAuth VP
        vpOptions = "{"
            + "  \"proofPurpose\": \"authentication\","
            + "  \"domain\": \"example.org\","
            + "  \"verificationMethod\": \"" + verificationMethod + "\""
            + "}";
        vp = DIDKit.DIDAuth(did, vpOptions, jwk);

        // Verify Presentation
        vpVerifyOptions = "{"
            + "  \"domain\": \"example.org\","
            + "  \"proofPurpose\": \"authentication\""
            + "}";
        vpResult = DIDKit.verifyPresentation(vp, vpVerifyOptions);
        assert vpResult.contains("\"errors\":[]");
    }
}
