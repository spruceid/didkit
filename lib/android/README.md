# DIDKit - Android

[Android Library (AAR file)][AAR] for DIDKit. The AAR file includes Java class files using [JNI][], and binary shared libraries for Android's supported architectures (x86, armeabi-v7a, arm64-v8a, x86\_64). It can be added to existing Android projects using Android Studio or Gradle.

## Requires

Android SDK and NDK, for Linux x86\_64

## Build

In the parent directory, run:
```
make target/didkit.aar
```

[AAR]: https://developer.android.com/studio/projects/android-library.html#aar-contents
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface
