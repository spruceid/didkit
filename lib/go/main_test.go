package didkit

import (
	"strings"
	"testing"
)

func errOrLog(t *testing.T, v interface{}, e error) {
	if e != nil {
		t.Errorf("error: %v", e)
	} else {
		t.Logf("%v", v)
	}
}

func TestKey(t *testing.T) {
	key, err := GenerateEd25519Key()
	errOrLog(t, key, err)

	did, err := KeyToDID("key", key)
	errOrLog(t, did, err)

	vm, err := KeyToVerificationMethod("key", key)
	errOrLog(t, vm, err)
}

func TestVCVP(t *testing.T) {
	key, err := GenerateEd25519Key()
	errOrLog(t, key, err)

	did, err := KeyToDID("key", key)
	errOrLog(t, did, err)

	vm, err := KeyToVerificationMethod("key", key)
	errOrLog(t, vm, err)

	credential := "{" +
		"   \"@context\": \"https://www.w3.org/2018/credentials/v1\"," +
		"   \"id\": \"http://example.org/credentials/3731\"," +
		"   \"type\": [\"VerifiableCredential\"]," +
		"   \"issuer\": \"" + did + "\"," +
		"   \"issuanceDate\": \"2020-08-19T21:41:50Z\"," +
		"   \"credentialSubject\": {" +
		"       \"id\": \"did:example:d23dd687a7dc6787646f2eb98d0\"" +
		"   }" +
		"}"

	vcOptions := "{" +
		"  \"proofPurpose\": \"assertionMethod\"," +
		"  \"verificationMethod\": \"" + vm + "\"" +
		"}"

	vc, err := IssueCredential(credential, vcOptions, key)
	errOrLog(t, vc, err)

	vcVerifyOptions := "{" +
		"  \"proofPurpose\": \"assertionMethod\"" +
		"}"
	vcResult, err := VerifyCredential(vc, vcVerifyOptions)
	errOrLog(t, vcResult, err)

	if !strings.Contains(vcResult, "\"errors\":[]") {
		t.Errorf("error: %v", vcResult)
	}

	presentation := "{" +
		"   \"@context\": [\"https://www.w3.org/2018/credentials/v1\"]," +
		"   \"id\": \"http://example.org/presentations/3731\"," +
		"   \"type\": [\"VerifiablePresentation\"]," +
		"   \"holder\": \"" + did + "\"," +
		"   \"verifiableCredential\": " + vc +
		"}"
	vpOptions := "{" +
		"  \"proofPurpose\": \"authentication\"," +
		"  \"verificationMethod\": \"" + vm + "\"" +
		"}"
	vp, err := IssuePresentation(presentation, vpOptions, key)
	errOrLog(t, vp, err)

	vpVerifyOptions := "{" +
		"  \"proofPurpose\": \"authentication\"" +
		"}"
	vpResult, err := VerifyPresentation(vp, vpVerifyOptions)
	errOrLog(t, vpResult, err)

	if !strings.Contains(vcResult, "\"errors\":[]") {
		t.Errorf("error: %v", vcResult)
	}
}

func TestResolveDID(t *testing.T) {
	key, err := GenerateEd25519Key()
	errOrLog(t, key, err)

	did, err := KeyToDID("key", key)
	errOrLog(t, did, err)

	resolution, err := ResolveDID(did, "{}")
	errOrLog(t, resolution, err)

	if !strings.Contains(resolution, "\"didDocument\":{") {
		t.Errorf("error: %v", resolution)
	}
}

func TestDereferenceDID(t *testing.T) {
	key, err := GenerateEd25519Key()
	errOrLog(t, key, err)

	vm, err := KeyToVerificationMethod("key", key)
	errOrLog(t, vm, err)

	dereferencing, err := DereferenceDIDUrl(vm, "{}")
	errOrLog(t, dereferencing, err)

	if !strings.HasPrefix(dereferencing, "[{") {
		t.Errorf("error: %v", dereferencing)
	}
}

func TestDIDAuth(t *testing.T) {
	key, err := GenerateEd25519Key()
	errOrLog(t, key, err)

	did, err := KeyToDID("key", key)
	errOrLog(t, did, err)

	vm, err := KeyToVerificationMethod("key", key)
	errOrLog(t, did, err)

	vpOptions := "{" +
		"  \"proofPurpose\": \"authentication\"," +
		"  \"domain\": \"example.org\"," +
		"  \"verificationMethod\": \"" + vm + "\"" +
		"}"
	vp, err := DIDAuth(did, vpOptions, key)
	errOrLog(t, vp, err)

	vpVerifyOptions := "{" +
		"  \"domain\": \"example.org\"," +
		"  \"proofPurpose\": \"authentication\"" +
		"}"
	vpResult, err := VerifyPresentation(vp, vpVerifyOptions)
	errOrLog(t, vpResult, err)

	if !strings.Contains(vpResult, "\"errors\":[]") {
		t.Errorf("error: %v", vpResult)
	}
}
