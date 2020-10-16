# DIDKit - Java

Java bindings for DIDKit, using [JNI][]. The [JAR][] file includes Java class files. To use this in an application, you must also include the shared library (`libdidkit.so`) in your application in your Java Library Path.

## Build

In the parent directory, run:
```
make ../target/didkit.jar
```

To build the shared library:
```
make ../target/release/libdidkit.so
```

## Android

For Android, you can use the separate [Android library (AAR file)](../android/) which includes the Java class files and compiled shared libraries.

[JAR]: https://en.wikipedia.org/wiki/JAR_(file_format)
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface
