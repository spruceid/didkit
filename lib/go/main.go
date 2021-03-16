package main

// #cgo LDFLAGS: -Wl,-R${SRCDIR} -L${SRCDIR} -ldidkit
// #include <didkit.h>
import "C"

import (
	"fmt"
)

type DIDKitError struct {
	code    int
	message string
}

func (e *DIDKitError) Error() string {
	return e.message
}

func NewDIDKitError() error {
	code := int(C.didkit_error_code())
	message := C.GoString(C.didkit_error_message())
	return &DIDKitError{code, message}
}

func generateEd25519Key() (string, error) {
	result_pointer := C.didkit_vc_generate_ed25519_key()
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func keyToDid(methodName string, key string) (string, error) {
	result_pointer := C.didkit_key_to_did(C.CString(methodName), C.CString(key))
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func keyToVerificationMethod(methodName string, key string) (string, error) {
	result_pointer := C.didkit_key_to_verification_method(
		C.CString(methodName), 
		C.CString(key)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func issueCredential(
	credential string,
	options string,
	key string)
(string, error) {
	result_pointer := C.didkit_vc_issue_credential(
		C.CString(credential),
		C.CString(options),
		C.CString(key)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func verifyCredential(credential string, options string) (string, error) {
	result_pointer := C.didkit_vc_verify_credential(
		C.CString(credential),
		C.CString(options)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func issuePresentation(
	presentation string,
	options string,
	key string
) (string, error) {
	result_pointer := C.didkit_vc_issue_presentation(
		C.CString(presentation),
		C.CString(options),
		C.CString(key)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func verifyPresentation(presentation string, options string) (string, error) {
	result_pointer := C.didkit_vc_verify_presentation(
		C.CString(presentation),
		C.CString(options)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func didResolve(did string, inputMetadata string) (string, error) {
	result_pointer := C.didkit_did_resolve(
		C.CString(did),
		C.CString(inputMetadata)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func didUrlDereference(didUrl string, inputMetadata string) (string, error) {
	result_pointer := C.didkit_did_url_dereference(
		C.CString(didUrl),
		C.CString(inputMetadata)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func didAuth(did string, options string, key string) (string, error) {
	result_pointer := C.didkit_did_auth(
		C.CString(did),
		C.CString(options),
		C.CString(key)
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", NewDIDKitError()
}

func getVersion() string {
	return C.GoString(C.didkit_get_version())
}

func main() {
	fmt.Println(getVersion())
	fmt.Println(generateEd25519Key())
	fmt.Println(keyToDid("", ""))
	fmt.Println(keyToVerificationMethod("", ""))
	fmt.Println(issueCredential("", "", ""))
	fmt.Println(verifyCredential("", ""))
	fmt.Println(issuePresentation("", "", ""))
	fmt.Println(verifyPresentation("", ""))
	fmt.Println(didResolve("", ""))
	fmt.Println(didUrlDereference("", ""))
	fmt.Println(didAuth("", "", ""))
	return
}
