import Foundation

public enum DIDKit {

  public struct Error: Swift.Error {
    public let code: Int32
    public let message: String

    init() {
      code = didkit_error_code()
      message = didkit_error_message().flatMap(String.init(cString:)) ?? ""
    }
  }

  public static func version() -> String {
    didkit_get_version().flatMap(String.init(cString:)) ?? ""
  }

  public static func generateEd25519Key() throws -> String {
    guard let keyPtr = didkit_vc_generate_ed25519_key() else {
      throw Error()
    }
    defer { didkit_free_string(keyPtr) }
    return String(cString: keyPtr)
  }

  public static func keyToDID(method: String, jwk: String) throws -> String {
    guard let didKeyPtr = didkit_key_to_did(method, jwk) else {
      throw Error()
    }
    defer { didkit_free_string(didKeyPtr) }
    return String(cString: didKeyPtr)
  }

  public static func keyToVerificationMethod(method: String, jwk: String) throws -> String {
    guard let vmPtr = didkit_key_to_verification_method(method, jwk) else {
      throw Error()
    }
    defer { didkit_free_string(vmPtr) }
    return String(cString: vmPtr)
  }

  public static func issueCredential(
    credential: String,
    options: String,
    jwk: String
  ) throws -> String {
    guard let vcPtr = didkit_vc_issue_credential(credential, options, jwk) else {
      throw Error()
    }
    defer { didkit_free_string(vcPtr) }
    return String(cString: vcPtr)
  }

  public static func verifyCredential(credential: String, options: String) throws -> String {
    guard let resultPtr = didkit_vc_verify_credential(credential, options) else {
      throw Error()
    }
    defer { didkit_free_string(resultPtr) }
    return String(cString: resultPtr)
  }

  public static func issuePresentation(
    presentation: String,
    options: String,
    jwk: String
  ) throws -> String {
    guard let presentationPtr = didkit_vc_issue_presentation(presentation, options, jwk) else {
      throw Error()
    }
    defer { didkit_free_string(presentationPtr) }
    return String(cString: presentationPtr)
  }

  public static func verifyPresentation(presentation: String, options: String) throws -> String {
    guard let resultPtr = didkit_vc_verify_presentation(presentation, options) else {
      throw Error()
    }
    defer { didkit_free_string(resultPtr) }
    return String(cString: resultPtr)
  }

  public static func resolveDID(did: String, inputMetadata: String) throws -> String {
    guard let resultPtr = didkit_did_resolve(did, inputMetadata) else {
      throw Error()
    }
    defer { didkit_free_string(resultPtr) }
    return String(cString: resultPtr)
  }

  public static func dereferenceDIDURL(didURL: String, inputMetadata: String) throws -> String {
    guard let resultPtr = didkit_did_url_dereference(didURL, inputMetadata) else {
      throw Error()
    }
    defer { didkit_free_string(resultPtr) }
    return String(cString: resultPtr)
  }

  public static func didAuth(holder: String, options: String, jwk: String) throws -> String {
    guard let vpPtr = didkit_did_auth(holder, options, jwk) else {
      throw Error()
    }
    defer { didkit_free_string(vpPtr) }
    return String(cString: vpPtr)
  }
}
