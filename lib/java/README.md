# DIDKit - Java

Java bindings for DIDKit, using [JNI][]. The [JAR][] file includes Java class files. To use this in an application, you must also include the shared library (`libdidkit.so`) in your application in your Java Library Path.

## Build

Run:
```sh
$ make -C ../ ../target/didkit.jar
```

To build the shared library for your current platform/architecture:
```sh
$ make -C ../ ../target/release/libdidkit.so
```

## Test

```sh
$ make -C ../ ../target/tests/java.stamp
```

## Android

For Android, build the separate [Android library (AAR file)](../android/) which includes the Java class files and shared libraries for all Android targets.

[JAR]: https://en.wikipedia.org/wiki/JAR_(file_format)
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface
