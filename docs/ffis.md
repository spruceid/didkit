---
id: ffis
title: Foreign Function Interfaces
---
[path-packages]: https://dart.dev/tools/pub/dependencies#path-packages
[packages-plugins]: https://flutter.dev/developing-packages/

DIDKit has bindings for various languages and environments. Each corresponding directory contains a README with additional info particular to it. The Makefile used to build all the libraries requires [GNU Make](https://www.gnu.org/software/make/).

Building and testing each library requires tools for the corresponding environment:

* C: C compiler and linker
* Java: JDK and JRE
* Android: [Android NDK](https://developer.android.com/ndk/), [SDK tools](https://developer.android.com/studio/), and Rust Android targets
* Flutter: [Flutter](https://github.com/flutter/flutter)
Build

To build all the libraries, run `make` in the `/lib/` directory of the DIDKit repo.

To build and test a particular library, see the instructions below.

## C

### Build

```sh
# from DIDKit root directory:
$ make -C lib ../target/release/libdidkit.so
```

### Test

```sh
# from DIDKit root directory:
$ make -C lib ../target/test/c.stamp
```

### + Android

To build the C shared library for Android targets, build the [DIDKit Android library](#android).

## Java

Java bindings for DIDKit, using [JNI][]. The [JAR][] file includes Java class files. To use this in an application, you must also include the shared library (`libdidkit.so`) in your application in your Java Library Path.

### Build

Run:
```sh
# from DIDKit root directory:
$ make -C lib ../target/didkit.jar
```

To build the shared library for your current platform/architecture:
```sh
# from DIDKit root directory:
$ make -C lib ../target/release/libdidkit.so
```

### Test

```sh
# from DIDKit root directory:
$ make -C lib ../target/tests/java.stamp
```

### + Android

For Android, build the separate [Android library (AAR file)](#android) which includes the Java class files and shared libraries for all Android targets.

[JAR]: https://en.wikipedia.org/wiki/JAR_(file_format)
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface


## Android

[Android Library (AAR file)][AAR] for DIDKit. The AAR file includes Java class files using [JNI][], and binary shared libraries for Android's supported architectures (x86, armeabi-v7a, arm64-v8a, x86\_64). The AAR can be added to existing Android projects using Android Studio or Gradle.

### Requires

Android SDK and NDK for Linux x86\_64. The Android SDK is expected to be installed at `~/Android/Sdk`. If it is somewhere else instead, you can specify it with a Make variable, e.g. `make ANDROID_SDK_ROOT=/other/location/android-sdk`. 

Rust Android targets are also required. To install those with `rustup`, run:
```sh
//from root directory of didkit project
$ make -C lib install-rustup-android
```

### Build

```sh
//from root directory of didkit project
$ make -C lib ../target/test/aar.stamp
```

#### Make variables

- `ANDROID_SDK_ROOT` - path to Android SDK. Default: `~/Android/Sdk`
- `ANDROID_TOOLS` - Android tools directory. Default is to pick one matching `$(ANDROID_SDK_ROOT)/build-tools/*`.
- `ANDROID_NDK_HOME` - Android NDK directory. Default is `$(ANDROID_SDK_ROOT)/ndk-bundle)` if exists, or one matching `$(ANDROID_SDK_ROOT)/ndk/*`.

[AAR]: https://developer.android.com/studio/projects/android-library.html#aar-contents
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface

## Flutter

[Flutter plugin][packages-plugins] for the DIDKit library. Includes Dart bindings, and functionality for Android and iOS (WIP).

Flutter Doctor and CLI tools are also required.

## Usage

You can depend on this plugin as a [path dependency][path-packages].

You will also need to build the DIDKit library for your target platforms.
To do that for Android, trigger building the AAR file:

```sh
# from DIDKit root directory:
make -C lib ../target/didkit.aar
```

