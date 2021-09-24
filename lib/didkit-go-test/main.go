package didkit

// #cgo LDFLAGS: -Wl,-R${SRCDIR} -L${SRCDIR} -ldidkit
// #include <didkit.h>
import "C"

type DIDKitError struct {
	code    int
	message string
}

func (e *DIDKitError) Error() string {
	return e.message
}

func GetDIDKitError() error {
	code := int(C.didkit_error_code())
	message := C.GoString(C.didkit_error_message())
	return &DIDKitError{code, message}
}

func GetVersion() string {
	return C.GoString(C.didkit_get_version())
}

func GenerateEd25519Key() (string, error) {
	result_pointer := C.didkit_vc_generate_ed25519_key()
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func KeyToDID(methodName string, key string) (string, error) {
	result_pointer := C.didkit_key_to_did(C.CString(methodName), C.CString(key))
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func KeyToVerificationMethod(methodName string, key string) (string, error) {
	result_pointer := C.didkit_key_to_verification_method(
		C.CString(methodName),
		C.CString(key),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func IssueCredential(
	credential string,
	options string,
	key string,
) (string, error) {
	result_pointer := C.didkit_vc_issue_credential(
		C.CString(credential),
		C.CString(options),
		C.CString(key),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func VerifyCredential(credential string, options string) (string, error) {
	result_pointer := C.didkit_vc_verify_credential(
		C.CString(credential),
		C.CString(options),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func IssuePresentation(
	presentation string,
	options string,
	key string,
) (string, error) {
	result_pointer := C.didkit_vc_issue_presentation(
		C.CString(presentation),
		C.CString(options),
		C.CString(key),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func VerifyPresentation(presentation string, options string) (string, error) {
	result_pointer := C.didkit_vc_verify_presentation(
		C.CString(presentation),
		C.CString(options),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func ResolveDID(did string, inputMetadata string) (string, error) {
	result_pointer := C.didkit_did_resolve(
		C.CString(did),
		C.CString(inputMetadata),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func DereferenceDIDUrl(didUrl string, inputMetadata string) (string, error) {
	result_pointer := C.didkit_did_url_dereference(
		C.CString(didUrl),
		C.CString(inputMetadata),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}

func DIDAuth(did string, options string, key string) (string, error) {
	result_pointer := C.didkit_did_auth(
		C.CString(did),
		C.CString(options),
		C.CString(key),
	)
	if result_pointer != nil {
		result := C.GoString(result_pointer)
		C.didkit_free_string(result_pointer)
		return result, nil
	}
	return "", GetDIDKitError()
}
