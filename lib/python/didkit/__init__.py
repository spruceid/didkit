from ctypes import *
from sys import platform
import os.path

didkit = None
didpath = os.path.dirname(os.path.abspath(__file__))

if platform == "linux" or platform == "linux2":
    didpath = os.path.join(didpath, 'libdidkit.so')
    didkit = libc = CDLL(didpath)
elif platform == "darwin":
    didpath = os.path.join(didpath, 'libdidkit.dylib')
    didkit = libc = CDLL(didpath)
else:
    didpath = os.path.join(didpath, 'libdidkit.dll')
    didkit = libc = CDLL(didpath, winmode=1)

# String getVersion()
didkit.didkit_get_version.restype = c_char_p
didkit.didkit_get_version.argtype = ()

# String didkit_error_message()
didkit.didkit_error_message.restype = c_char_p
didkit.didkit_error_message.argtype = ()

# int didkit_error_code()
didkit.didkit_error_code.restype = c_int32
didkit.didkit_error_code.argtype = ()

# String generateEd25519Key()
didkit.didkit_vc_generate_ed25519_key.restype = c_void_p
didkit.didkit_vc_generate_ed25519_key.argtype = ()

# String keyToDID(String methodPattern, String key)
didkit.didkit_key_to_did.restype = c_void_p
didkit.didkit_key_to_did.argtype = (c_char_p, c_char_p)

# String keyToVerificationMethod(String methodPattern, String key)
didkit.didkit_key_to_verification_method.restype = c_void_p
didkit.didkit_key_to_verification_method.argtype = (c_char_p, c_char_p)

# String issueCredential(String credential, String options, String key)
didkit.didkit_vc_issue_credential.restype = c_void_p
didkit.didkit_vc_issue_credential.argtype = (c_char_p, c_char_p, c_char_p)

# String verifyCredential(String credential, String options)
didkit.didkit_vc_verify_credential.restype = c_void_p
didkit.didkit_vc_verify_credential.argtype = (c_char_p, c_char_p)

# String issuePresentation(String presentation, String options, String key)
didkit.didkit_vc_issue_presentation.restype = c_void_p
didkit.didkit_vc_issue_presentation.argtype = (c_char_p, c_char_p, c_char_p)

# String verifyPresentation(String presentation, String options)
didkit.didkit_vc_verify_presentation.restype = c_void_p
didkit.didkit_vc_verify_presentation.argtype = (c_char_p, c_char_p)

# String resolveDID(String did, String inputMetadata)
didkit.didkit_did_resolve.restype = c_void_p
didkit.didkit_did_resolve.argtype = (c_char_p, c_char_p)

# String dereferenceDIDURL(String didUrl, String inputMetadata)
didkit.didkit_did_url_dereference.restype = c_void_p
didkit.didkit_did_url_dereference.argtype = (c_char_p, c_char_p)

# String DIDAuth(String did, String options, String key)
didkit.didkit_did_auth.restype = c_void_p
didkit.didkit_did_auth.argtype = (c_char_p, c_char_p, c_char_p)

# void didkit_free_string(String str)
didkit.didkit_free_string.restype = None
didkit.didkit_free_string.argtype = (c_void_p)


class DIDKitException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    @staticmethod
    def lastError():
        code = didkit.didkit_error_code()
        message = didkit.didkit_error_message()
        message_str = 'Unable to get error message' if not message else message.decode()
        return DIDKitException(code, message_str)


def getVersion():
    return didkit.didkit_get_version().decode()


def generateEd25519Key():
    key = didkit.didkit_vc_generate_ed25519_key()
    if not key:
        raise DIDKitException.lastError()
    key_str = cast(key, c_char_p).value.decode()
    didkit.didkit_free_string(cast(key, c_void_p))
    return key_str


def keyToDID(methodPattern, key):
    did = didkit.didkit_key_to_did(methodPattern.encode(), key.encode())
    if not did:
        raise DIDKitException.lastError()
    did_str = cast(did, c_char_p).value.decode()
    didkit.didkit_free_string(cast(did, c_void_p))
    return did_str


def keyToVerificationMethod(methodPattern, key):
    vm = didkit.didkit_key_to_verification_method(methodPattern.encode(),
                                                  key.encode())
    if not vm:
        raise DIDKitException.lastError()
    vm_str = cast(vm, c_char_p).value.decode()
    didkit.didkit_free_string(cast(vm, c_void_p))
    return vm_str


def issueCredential(credential, options, key):
    vc = didkit.didkit_vc_issue_credential(credential.encode(),
                                           options.encode(), key.encode())
    if not vc:
        raise DIDKitException.lastError()
    vc_str = cast(vc, c_char_p).value.decode()
    didkit.didkit_free_string(cast(vc, c_void_p))
    return vc_str


def verifyCredential(credential, options):
    result = didkit.didkit_vc_verify_credential(credential.encode(),
                                                options.encode())
    if not result:
        raise DIDKitException.lastError()
    result_str = cast(result, c_char_p).value.decode()
    didkit.didkit_free_string(cast(result, c_void_p))
    return result_str


def issuePresentation(presentation, options, key):
    vp = didkit.didkit_vc_issue_presentation(presentation.encode(),
                                             options.encode(), key.encode())
    if not vp:
        raise DIDKitException.lastError()
    vp_str = cast(vp, c_char_p).value.decode()
    didkit.didkit_free_string(cast(vp, c_void_p))
    return vp_str


def verifyPresentation(presentation, options):
    result = didkit.didkit_vc_verify_presentation(presentation.encode(),
                                                  options.encode())
    if not result:
        raise DIDKitException.lastError()
    result_str = cast(result, c_char_p).value.decode()
    didkit.didkit_free_string(cast(result, c_void_p))
    return result_str


def resolveDID(did, inputMetadata):
    result = didkit.didkit_did_resolve(did.encode(), inputMetadata.encode())
    if not result:
        raise DIDKitException.lastError()
    result_str = cast(result, c_char_p).value.decode()
    didkit.didkit_free_string(cast(result, c_void_p))
    return result_str


def dereferenceDIDURL(didUrl, inputMetadata):
    result = didkit.didkit_did_url_dereference(didUrl.encode(),
                                               inputMetadata.encode())
    if not result:
        raise DIDKitException.lastError()
    result_str = cast(result, c_char_p).value.decode()
    didkit.didkit_free_string(cast(result, c_void_p))
    return result_str


def DIDAuth(did, options, key):
    vp = didkit.didkit_did_auth(did.encode(), options.encode(), key.encode())
    if not vp:
        raise DIDKitException.lastError()
    vp_str = cast(vp, c_char_p).value.decode()
    didkit.didkit_free_string(cast(vp, c_void_p))
    return vp_str
