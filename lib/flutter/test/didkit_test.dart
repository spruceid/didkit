import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:didkit/didkit.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('getVersion', () async {
    expect(DIDKit.getVersion(), isInstanceOf<String>());
  });
}
