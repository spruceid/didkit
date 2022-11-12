#import "DIDKitFlutterPlugin.h"

#import "didkit.h"

@implementation DIDKitFlutterPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar> *)registrar {
}

+ (void)dummyMethodToEnforceFunctionsDontGetOptmized {
  // Here we MUST call all functions from didkit.h so that they don't get
  // optimized and removed from release builds.
  didkit_get_version();
  didkit_did_auth(NULL, NULL, NULL);
  didkit_resolve_did(NULL, NULL);
  didkit_dereference_did_url(NULL, NULL);
  didkit_error_code();
  didkit_error_message();
  didkit_free_string(NULL);
  didkit_key_to_did(NULL, NULL);
  didkit_key_to_verification_method(NULL, NULL);
  didkit_generate_ed25519_key();
  didkit_generate_secp256r1_key();
  didkit_generate_secp256k1_key();
  didkit_generate_secp384r1_key();
  didkit_vc_issue_credential(NULL, NULL, NULL);
  didkit_vc_issue_presentation(NULL, NULL, NULL);
  didkit_vc_verify_credential(NULL, NULL);
  didkit_vc_verify_presentation(NULL, NULL);
  didkit_vc_prepare_issue_credential(NULL, NULL, NULL);
  didkit_vc_complete_issue_credential(NULL, NULL, NULL);
  didkit_vc_prepare_issue_presentation(NULL, NULL, NULL);
  didkit_vc_complete_issue_presentation(NULL, NULL, NULL);
}
@end
