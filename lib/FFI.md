# DIDKit FFI

DIDKit has bindings for various languages and environments. Each corresponding directory contains a README with additional info particular to it:

- [C](c/)
- [Java](java/)
- [Android](android/)
- [Flutter](flutter/)

## Dependencies

The Makefile used to build the libraries requires [GNU Make][].

Building and testing each library requires tools for the corresponding environment:
- C: C compiler and linker
- Java: JDK and JRE
- Android: [Android NDK][], [SDK tools][Android SDK], and Rust Android targets
- Flutter: [Flutter][]

## Build

To build all the libraries, run `make` in this directory.

To build and test a particular library, see the instructions in the corresponding readme.

[GNU Make]: https://www.gnu.org/software/make/
[Android NDK]: https://developer.android.com/ndk/
[Android SDK]: https://developer.android.com/studio/
[Flutter]: https://github.com/flutter/flutter
