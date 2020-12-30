library DIDKit;

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// TODO: support macOS, Windows
final DynamicLibrary lib = Platform.isAndroid || Platform.isLinux
  ? DynamicLibrary.open("libdidkit.so")
  : DynamicLibrary.process();

final get_version = lib
  .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('didkit_get_version');

final get_error_message = lib
  .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('didkit_error_message');

final get_error_code = lib
  .lookupFunction<Int32 Function(), int Function()>('didkit_error_code');

final generate_ed25519_key = lib
  .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('didkit_vc_generate_ed25519_key');

final key_to_did_key = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>)>('didkit_key_to_did');

final key_to_verification_method = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>)>('didkit_key_to_verification_method');

final key_to_did_tezos = lib
    .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>)>('didkit_key_to_did_tezos');

final issue_credential = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>)>('didkit_vc_issue_credential');

final verify_credential = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('didkit_vc_verify_credential');

final issue_presentation = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>)>('didkit_vc_issue_presentation');

final verify_presentation = lib
  .lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('didkit_vc_verify_presentation');

final free_string = lib
  .lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('didkit_free_string');

class DIDKitException implements Exception {
  int code;
  String message;
  DIDKitException(this.code, this.message);
  String toString() {
    return "DIDKitException ($code): $message";
  }
}

DIDKitException lastError() {
  final code = get_error_code();
  final message_utf8 = get_error_message();
  final message_string = message_utf8.address == nullptr.address
    ? "Unable to get error message"
    : Utf8.fromUtf8(message_utf8);

  return new DIDKitException(code, message_string);
}

class DIDKit {

  static String getVersion() {
    return Utf8.fromUtf8(get_version());
  }

  static String generateEd25519Key() {
    final key = generate_ed25519_key();
    if (key.address == nullptr.address) throw lastError();
    final key_string = Utf8.fromUtf8(key);
    free_string(key);
    return key_string;
  }

  static String keyToDIDKey(String key) {
    final did_key = key_to_did_key(Utf8.toUtf8(key));
    if (did_key.address == nullptr.address) throw lastError();
    final did_key_string = Utf8.fromUtf8(did_key);
    free_string(did_key);
    return did_key_string;
  }

  static String keyToVerificationMethod(String key) {
    final vm = key_to_verification_method(Utf8.toUtf8(key));
    if (vm.address == nullptr.address) throw lastError();
    final vm_string = Utf8.fromUtf8(vm);
    free_string(vm);
    return vm_string;
  }

  static String keyToDIDTezos(String key) {
    final vm = key_to_did_tezos(Utf8.toUtf8(key));
    if (vm.address == nullptr.address) throw lastError();
    final vm_string = Utf8.fromUtf8(vm);
    free_string(vm);
    return vm_string;
  }

  static String issueCredential(String credential, String options, String key) {
    final vc = issue_credential(Utf8.toUtf8(credential), Utf8.toUtf8(options), Utf8.toUtf8(key));
    if (vc.address == nullptr.address) throw lastError();
    final vc_string = Utf8.fromUtf8(vc);
    free_string(vc);
    return vc_string;
  }

  static String verifyCredential(String credential, String options) {
    final result = verify_credential(Utf8.toUtf8(credential), Utf8.toUtf8(options));
    if (result.address == nullptr.address) throw lastError();
    final result_string = Utf8.fromUtf8(result);
    free_string(result);
    return result_string;
  }

  static String issuePresentation(String presentation, String options, String key) {
    final vp = issue_presentation(Utf8.toUtf8(presentation), Utf8.toUtf8(options), Utf8.toUtf8(key));
    if (vp.address == nullptr.address) throw lastError();
    final vp_string = Utf8.fromUtf8(vp);
    free_string(vp);
    return vp_string;
  }

  static String verifyPresentation(String presentation, String options) {
    final result = verify_presentation(Utf8.toUtf8(presentation), Utf8.toUtf8(options));
    if (result.address == nullptr.address) throw lastError();
    final result_string = Utf8.fromUtf8(result);
    free_string(result);
    return result_string;
  }

}
