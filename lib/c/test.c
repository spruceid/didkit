#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "didkit.h"

int main() {
    const char *version = didkit_get_version();
    assert(version != NULL);
    assert(strlen(version) > 0);

    // Trigger error
    const char *vp = didkit_vc_issue_presentation("{}", "{}", "{}");
    assert(vp == NULL);
    const char *error_msg = didkit_error_message();
    assert(error_msg != NULL);
    assert(strlen(error_msg) > 0);
    int error_code = didkit_error_code();
    assert(error_code != 0);

    // Generate key
    const char *key = didkit_vc_generate_ed25519_key();
    if (key == NULL) errx(1, "generate key: %s", didkit_error_message());

    // Get did:key for key
    const char *did = didkit_key_to_did("key", key);
    if (did == NULL) errx(1, "key to did: %s", didkit_error_message());

    // Get verificationMethod for key
    const char *verification_method = didkit_key_to_verification_method("key", key);
    if (verification_method == NULL) errx(1, "key to vm: %s", didkit_error_message());

    // Issue Credential (LDP)
    char credential[0x1000];
    snprintf(credential, sizeof(credential), "{"
        "   \"@context\": \"https://www.w3.org/2018/credentials/v1\","
        "   \"id\": \"http://example.org/credentials/3731\","
        "   \"type\": [\"VerifiableCredential\"],"
        "   \"issuer\": \"%s\","
        "   \"issuanceDate\": \"2020-08-19T21:41:50Z\","
        "   \"credentialSubject\": {"
        "       \"id\": \"did:example:d23dd687a7dc6787646f2eb98d0\""
        "   }"
        "}", did);
    char vc_options[0x1000];
    snprintf(vc_options, sizeof vc_options, "{"
            "  \"proofPurpose\": \"assertionMethod\","
            "  \"verificationMethod\": \"%s\""
            "}", verification_method);
    const char *vc_ldp = didkit_vc_issue_credential(credential, vc_options, key);
    if (vc_ldp == NULL) errx(1, "issue credential (LDP): %s", didkit_error_message());

    // Issue credential (JWT)
    snprintf(vc_options, sizeof vc_options, "{"
            "  \"proofPurpose\": \"assertionMethod\","
            "  \"proofFormat\": \"jwt\","
            "  \"verificationMethod\": \"%s\""
            "}", verification_method);
    const char *vc_jwt = didkit_vc_issue_credential(credential, vc_options, key);
    if (vc_jwt == NULL) errx(1, "issue credential (JWT): %s", didkit_error_message());

    // Verify Credential (LDP)
    const char *vc_verify_options = "{\"proofPurpose\": \"assertionMethod\"}";
    const char *res = didkit_vc_verify_credential(vc_ldp, vc_verify_options);
    if (res == NULL) errx(1, "verify credential (LDP): %s", didkit_error_message());
    if (strstr(res, "\"errors\":[]") == NULL) errx(1, "verify credential (LDP) result: %s", res);
    didkit_free_string(res);

    // Verify Credential (JWT)
    vc_verify_options = "{\"proofFormat\": \"jwt\"}";
    res = didkit_vc_verify_credential(vc_jwt, vc_verify_options);
    if (res == NULL) errx(1, "verify credential (JWT): %s", didkit_error_message());
    if (strstr(res, "\"errors\":[]") == NULL) errx(1, "verify credential (JWT) result: %s", res);
    didkit_free_string(res);

    // Issue Presentation
    char presentation[0x1000];
    snprintf(presentation, sizeof presentation, "{"
        "   \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],"
        "   \"id\": \"http://example.org/presentations/3731\","
        "   \"type\": [\"VerifiablePresentation\"],"
        "   \"holder\": \"%s\","
        "   \"verifiableCredential\": %s"
        "}", did, vc_ldp);
    char vp_options[0x1000];
    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"verificationMethod\": \"%s\""
            "}", verification_method);
    vp = didkit_vc_issue_presentation(presentation, vp_options, key);
    if (vp == NULL) errx(1, "issue presentation: %s", didkit_error_message());

    // Verify Presentation
    const char *vp_verify_options = "{\"proofPurpose\": \"authentication\"}";
    res = didkit_vc_verify_presentation(vp, vp_verify_options);
    if (res == NULL) errx(1, "verify presentation: %s", didkit_error_message());
    if (strstr(res, "\"errors\":[]") == NULL) errx(1, "verify presentation result: %s", res);
    didkit_free_string(res);

    didkit_free_string(vp);
    didkit_free_string(vc_ldp);

    // Resolve DID
    const char *did_doc = didkit_did_resolve(did, NULL);
    if (did_doc == NULL) errx(1, "resolve DID: %s", didkit_error_message());
    if (strstr(did_doc, "\"didDocument\":{") == NULL) errx(1, "DID resolution result: %s", did_doc);
    didkit_free_string(did_doc);

    // Dereference DID URL
    const char *result = didkit_did_url_dereference(verification_method, NULL);
    if (result == NULL) errx(1, "Dereference DID URL: %s", didkit_error_message());
    if (strncmp(result, "[{", 2) != 0) errx(1, "DID dereferencing result: %s", result);
    didkit_free_string(result);

    // Generate a DIDAuth Verifiable Presentation (LDP).
    // Prepare challenge and domain for VP request
    srand(time(NULL));
    int challenge = rand();
    // Generate VP
    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"verificationMethod\": \"%s\","
            "  \"challenge\": \"%d\""
            "}", verification_method, challenge);
    vp = didkit_did_auth(did, vp_options, key);
    if (vp == NULL) errx(1, "DIDAuth (LDP): %s", didkit_error_message());

    // Generate a DIDAuth Verifiable Presentation (JWT).
    int challenge_jwt = rand();
    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"verificationMethod\": \"%s\","
            "  \"proofFormat\": \"jwt\","
            "  \"challenge\": \"%d\""
            "}", verification_method, challenge_jwt);
    const char *vp_jwt = didkit_did_auth(did, vp_options, key);
    if (vp_jwt == NULL) errx(1, "DIDAuth (JWT): %s", didkit_error_message());

    // Verify DIDAuth Presentation (LDP)
    char didauth_vp_verify_options[0x1000];
    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"challenge\": \"%d\""
            "}", challenge);
    res = didkit_vc_verify_presentation(vp, vp_options);
    if (res == NULL) errx(1, "verify DIDAuth (LDP): %s", didkit_error_message());
    if (strstr(res, "\"errors\":[]") == NULL) errx(1, "verify DIDAuth result (LDP): %s", res);
    didkit_free_string(res);
    didkit_free_string(vp);

    // Verify DIDAuth Presentation (JWT)
    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"proofFormat\": \"jwt\","
            "  \"challenge\": \"%d\""
            "}", challenge_jwt);
    res = didkit_vc_verify_presentation(vp_jwt, vp_options);
    if (res == NULL) errx(1, "verify DIDAuth (JWT): %s", didkit_error_message());
    if (strstr(res, "\"errors\":[]") == NULL) errx(1, "verify DIDAuth result (JWT): %s", res);
    didkit_free_string(res);
    didkit_free_string(vp_jwt);

    didkit_free_string(verification_method);
    didkit_free_string(did);
    didkit_free_string(key);
}
