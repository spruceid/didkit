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
	$(TARGET)/test/aar.stamp \
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

$(TARGET)/cabi-test: c/test.c $(TARGET)/release/libdidkit.so $(TARGET)/didkit.h
	$(CC) -I$(TARGET) -L$(TARGET)/release $< -ldl -ldidkit -o $@

## Python
$(TARGET)/test/python.stamp: $(TARGET)/release/$(LIB_NAME) | $(TARGET)/test
	rm -rf python/dist/*
	python3 -m pip install --upgrade pip build
	python3 -m build python/
	touch $@

.PHONY: install-python
install-python: $(TARGET)/test/python.stamp
	python3 -m pip install python/dist/didkit-*.whl
	python3 -m unittest python/didkit/tests.py -v

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
	cd swift && \
		xcodebuild test \
			-destination platform="iOS Simulator,name=iPhone 12 Pro,OS=14.5" \
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
WASM_SRC=web/loader/wasm/package.json web/loader/wasm/webpack.config.js web/loader/wasm/didkit-loader.js $(WEB_SRC)

.PHONY: install-wasm-pack
install-wasm-pack:
	 curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh 

$(TARGET)/test/wasm.stamp: $(WASM_SRC) | $(TARGET)/test
	cd web && wasm-pack build --target web --out-dir pkg/wasm
	npm --prefix web/loader/wasm install
	npm --prefix web/loader/wasm run build
	touch $@

## WASM-ASM-JS

ASM_SRC=web/loader/asmjs/package.json web/loader/asmjs/webpack.config.js $(WEB_SRC)

BINARYEN_ROOT?="$(HOME)/binaryen"

$(TARGET)/test/asmjs.stamp: $(ASM_SRC) | $(TARGET)/test
	cd web && wasm-pack build --target bundler --out-dir pkg/asmjs
	cd web/pkg/asmjs && $(BINARYEN_ROOT)/bin/wasm2js --pedantic -o didkit_wasm_bg1.js didkit_wasm_bg.wasm
	cd web/loader/asmjs && ./repack.sh
	npm --prefix web/loader/asmjs install
	npm --prefix web/loader/asmjs run build
	npm --prefix web/loader/asmjs run test
	touch $@ 

## Cleanup

.PHONY: clean
clean:
	cargo clean
