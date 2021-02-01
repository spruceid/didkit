#import "DIDKitFlutterPlugin.h"

#import "didkit.h"

@implementation DIDKitFlutterPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
}
+ (void)dummyMethodToEnforceBuilding {
  didkit_get_version();
}
@end
