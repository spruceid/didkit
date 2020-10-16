library DIDKit;

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

typedef get_version_func = Pointer<Utf8> Function();
typedef GetVersion = Pointer<Utf8> Function();

// TODO: support macOS
final DynamicLibrary lib = Platform.isAndroid || Platform.isLinux
  ? DynamicLibrary.open("libdidkit.so")
  : DynamicLibrary.process();

final GetVersion get_version = lib
  .lookup<NativeFunction<get_version_func>>('didkit_get_version')
  .asFunction();

class DIDKit {
  static String getVersion() {
    return Utf8.fromUtf8(get_version());
  }
}
