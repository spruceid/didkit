# DIDKit - Flutter

[Flutter plugin][packages-plugins] for the DIDKit library. Includes Dart bindings, and functionality for Android and iOS (WIP).

## Usage

You can depend on this plugin as a [path dependency][path-packages].

You will also need to build the DIDKit library for your target platforms.
To do that for Android, trigger building the AAR file:
```
make -C ../ ../target/didkit.aar
```

[path-packages]: https://dart.dev/tools/pub/dependencies#path-packages
[packages-plugins]: https://flutter.dev/developing-packages/
