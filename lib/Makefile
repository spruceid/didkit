# didkit/lib/Makefile

TARGET=../target
ifeq ($(OS),Windows_NT)
	OS_NAME=Windows_NT
else
	OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
endif

ifeq ($(OS_NAME),darwin)
	LIB_NAME=libdidkit.dylib
else 
	LIB_NAME=libdidkit.so
endif

.PHONY: test
test: $(TARGET)/test/c.stamp \
	$(TARGET)/test/java.stamp \
	$(TARGET)/test/android.stamp \
	$(TARGET)/test/flutter.stamp \
	$(TARGET)/test/node.stamp \
	$(TARGET)/test/wasm.stamp

## Setup

android/res $(TARGET)/test $(TARGET)/jvm:
	mkdir -p $@

## Rust

RUST_SRC=Cargo.toml $(wildcard src/*.rs src/*/*.rs src/*/*/*.rs)

$(TARGET)/didkit.h: cbindgen.toml cbindings/build.rs cbindings/Cargo.toml $(RUST_SRC)
	cargo build -p didkit-cbindings
	test -s $@ && touch $@

$(TARGET)/release/$(LIB_NAME): $(RUST_SRC)
	cargo build --lib --release
	strip $@ || true

## C

$(TARGET)/test/c.stamp: $(TARGET)/cabi-test $(TARGET)/release/$(LIB_NAME) | $(TARGET)/test
	LD_LIBRARY_PATH=$(TARGET)/release $(TARGET)/cabi-test
	touch $@

$(TARGET)/cabi-test: c/test.c $(TARGET)/release/$(LIB_NAME) $(TARGET)/didkit.h
	$(CC) -I$(TARGET) -L$(TARGET)/release $< -ldl -ldidkit -o $@

## Java

JAVA_SRC=$(wildcard java/*/*/*.java java/*/*/*/*.java java/*/*/*/*/*.java)

$(TARGET)/test/java.stamp: \
	$(TARGET)/jvm/com/spruceid/DIDKit.class \
	$(TARGET)/jvm/com/spruceid/DIDKitException.class \
	$(TARGET)/jvm/com/spruceid/DIDKitTest.class \
	$(TARGET)/release/$(LIB_NAME) | $(TARGET)/test
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
TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64
ANDROID_LIBS=\
	$(TARGET)/i686-linux-android/release/libdidkit.so\
	$(TARGET)/armv7-linux-androideabi/release/libdidkit.so\
	$(TARGET)/aarch64-linux-android/release/libdidkit.so\
	$(TARGET)/x86_64-linux-android/release/libdidkit.so

$(TARGET)/test/android.stamp: $(TARGET)/didkit.jar $(ANDROID_LIBS) | $(TARGET)/test
	touch $@

$(TARGET)/%/release/libdidkit.so: $(RUST_SRC)
	PATH=$(TOOLCHAIN)/bin:"$(PATH)" \
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

$(TARGET)/test/ios.stamp: $(TARGET)/universal/release/libdidkit.a $(TARGET)/didkit.h | $(TARGET)/test
	cd ios && \
		xcodebuild test \
			-destination platform="iOS Simulator,name=iPhone 12 Pro" \
			-scheme DIDKitSwift
	touch $@

$(TARGET)/universal/release/libdidkit.a: $(IOS_LIBS)
	mkdir -p $(TARGET)/universal/release
	lipo -create $^ -output $@

$(TARGET)/%/release/libdidkit.a: $(RUST_SRC)
	cargo build --lib --release --target $*
	#strip $@

## Flutter

$(TARGET)/test/flutter.stamp: flutter/lib/didkit.dart flutter/test/didkit_test.dart $(TARGET)/release/$(LIB_NAME) | $(TARGET)/test
	cd flutter && LD_LIBRARY_PATH=$(shell pwd)/flutter \
		flutter --suppress-analytics test
	touch $@

## Node

NODE_SRC=node/package.json node/index.js node/Cargo.toml $(wildcard node/src/*.rs)

$(TARGET)/test/node.stamp: $(NODE_SRC) | $(TARGET)/test
	cd node && npm install
	cd node && npm run test
	touch $@

## WASM

WEB_SRC=web/Cargo.toml $(wildcard web/src/*.rs)

.PHONY: install-wasm-pack
install-wasm-pack:
	 curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

$(TARGET)/test/wasm.stamp: $(WEB_SRC) | $(TARGET)/test
	cd web && wasm-pack build --target web --out-dir pkg/web
	echo "No test was run"
	# TODO write automated tests for at least Node.js, and maybe for the bundled output format.
	# The existing web app installation didn't really make sense as the (dependency) installation has changed.
	touch $@

## Cleanup

.PHONY: clean
clean:
	cargo clean
