# didkit/lib/Makefile

TARGET=../target

.PHONY: test
test: $(TARGET)/test/c.stamp \
	$(TARGET)/test/java.stamp \
	$(TARGET)/test/aar.stamp \
	$(TARGET)/test/flutter.stamp

## Setup

android/res $(TARGET)/test $(TARGET)/jvm:
	mkdir -p $@

## Rust

RUST_SRC=Cargo.toml $(wildcard src/*.rs src/*/*.rs src/*/*/*.rs)

$(TARGET)/didkit.h: cbindgen.toml cbindings/build.rs cbindings/Cargo.toml $(RUST_SRC)
	cargo build -p didkit_cbindings
	test -s $@ && touch $@

$(TARGET)/release/libdidkit.so: $(RUST_SRC)
	cargo build --lib --release
	strip $@

## C

$(TARGET)/test/c.stamp: $(TARGET)/cabi-test $(TARGET)/release/libdidkit.so | $(TARGET)/test
	LD_LIBRARY_PATH=$(TARGET)/release $(TARGET)/cabi-test
	touch $@

$(TARGET)/cabi-test: c/test.c $(TARGET)/release/libdidkit.so $(TARGET)/didkit.h
	$(CC) -I$(TARGET) -L$(TARGET)/release $< -ldl -ldidkit -o $@

## Java

JAVA_SRC=$(wildcard java/*/*/*.java java/*/*/*/*.java java/*/*/*/*/*.java)

$(TARGET)/test/java.stamp: \
	$(TARGET)/jvm/com/spruceid/DIDKit.class \
	$(TARGET)/jvm/com/spruceid/DIDKitException.class \
	$(TARGET)/jvm/com/spruceid/DIDKitTest.class \
	$(TARGET)/release/libdidkit.so | $(TARGET)/test
	java -Djava.class.path=$(TARGET)/jvm \
		-Djava.library.path=$(TARGET)/release \
		com.spruceid.DIDKitTest
	touch $@

$(TARGET)/jvm/%.class: java/main/%.java | $(TARGET)/jvm
	javac $^ -d $(TARGET)/jvm -cp java/main -source 1.7 -target 1.7

$(TARGET)/jvm/%.class: java/test/%.java | $(TARGET)/jvm
	javac $^ -d $(TARGET)/jvm -cp java/main -source 1.7 -target 1.7

$(TARGET)/com_spruceid_DIDKit.h: java/main/com/spruceid/DIDKit.java
	javac -h $(TARGET) $<

$(TARGET)/didkit.jar: \
	$(TARGET)/jvm/com/spruceid/DIDKit.class \
	$(TARGET)/jvm/com/spruceid/DIDKitException.class
	jar -cf $@ $(patsubst $(TARGET)/jvm/%,-C $(TARGET)/jvm %,$^)

## Android

.PHONY: install-rustup-android
install-rustup-android:
	rustup target add i686-linux-android armv7-linux-androideabi aarch64-linux-android x86_64-linux-android

ANDROID_SDK_ROOT ?= ~/Android/Sdk
ANDROID_TOOLS ?= $(lastword $(wildcard $(ANDROID_SDK_ROOT)/build-tools/*))
ANDROID_NDK_HOME ?= $(lastword $(wildcard \
					$(ANDROID_SDK_ROOT)/ndk/* \
					$(ANDROID_SDK_ROOT)/ndk-bundle))
OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64
ANDROID_LIBS=\
	$(TARGET)/i686-linux-android/release/libdidkit.so\
	$(TARGET)/armv7-linux-androideabi/release/libdidkit.so\
	$(TARGET)/aarch64-linux-android/release/libdidkit.so\
	$(TARGET)/x86_64-linux-android/release/libdidkit.so

$(TARGET)/test/aar.stamp: $(TARGET)/didkit.aar | $(TARGET)/test
	rm -rf tmp/test-aar
	mkdir -p tmp/test-aar
	cd tmp/test-aar && unzip -q ../../$< || unzip -l ../../$< 
	cd tmp/test-aar && unzip -qo classes.jar com/spruceid/DIDKit.class || unzip -l classes.jar
	javap tmp/test-aar/com/spruceid/DIDKit.class | grep -q 'public class com.spruceid.DIDKit'
	touch $@

$(TARGET)/didkit.aar: $(TARGET)/didkit.jar android/AndroidManifest.xml android/R.txt $(ANDROID_LIBS) | android/res
	$(ANDROID_TOOLS)/aapt package -f -S android/res -F $@ --ignore-assets '.*:*~:README.md' android

$(TARGET)/%/release/libdidkit.so: $(RUST_SRC)
	PATH=$(TOOLCHAIN)/bin:$(PATH) \
	cargo build --lib --release --target $*
	$(TOOLCHAIN)/bin/llvm-strip $@

## iOS

.PHONY: install-rustup-ios
install-rustup-ios:
	rustup target add \
		aarch64-apple-ios \
		x86_64-apple-ios

IOS_LIBS=\
	$(TARGET)/aarch64-apple-ios/release/libdidkit.a \
	$(TARGET)/x86_64-apple-ios/release/libdidkit.a

$(TARGET)/test/ios.stamp: $(TARGET)/libdidkit.a | $(TARGET)/test
	touch $@

$(TARGET)/libdidkit.a: $(IOS_LIBS)
	lipo -create $^ -output $@

$(TARGET)/%/release/libdidkit.a: $(RUST_SRC)
	cargo build --lib --release --target $*
	#$(TOOLCHAIN)/bin/llvm-strip $@

## Flutter

$(TARGET)/test/flutter.stamp: flutter/lib/didkit.dart flutter/test/didkit_test.dart $(TARGET)/release/libdidkit.so | $(TARGET)/test
	cd flutter && LD_LIBRARY_PATH=$$PWD \
		flutter --suppress-analytics test
	touch $@

## Cleanup

.PHONY: clean
clean:
	cargo clean
