# didkit/lib/Makefile

TARGET=../target
ifeq ($(OS),Windows_NT)
	OS_NAME=Windows_NT
else
	OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
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

$(TARGET)/test/ios.stamp: $(TARGET)/universal/release/libdidkit.a | $(TARGET)/test
	touch $@

$(TARGET)/universal/release/libdidkit.a: $(IOS_LIBS)
	mkdir -p $(TARGET)/universal/release
	lipo -create $^ -output $@

$(TARGET)/%/release/libdidkit.a: $(RUST_SRC)
	cargo build --lib --release --target $*
	#$(TOOLCHAIN)/bin/llvm-strip $@

## Flutter

$(TARGET)/test/flutter.stamp: flutter/lib/didkit.dart flutter/test/didkit_test.dart $(TARGET)/release/libdidkit.so | $(TARGET)/test
	cd flutter && LD_LIBRARY_PATH=$$PWD \
		flutter --suppress-analytics test
	touch $@

## Node

NODE_SRC=node/package.json node/lib/index.js node/native/Cargo.toml $(wildcard node/native/src/*.rs)

$(TARGET)/test/node.stamp: $(NODE_SRC) | $(TARGET)/test
	cd node && npm install
	cd node && npm run build
	cd node && npm run test
	touch $@

## WASM

WASM_SRC=wasm/Cargo.toml wasm/loader/package.json wasm/loader/webpack.config.js wasm/loader/didkit-loader.js $(wildcard wasm/src/*.rs)

.PHONY: install-wasm-pack
install-wasm-pack:
	 curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh 

$(TARGET)/test/wasm.stamp: $(WASM_SRC) | $(TARGET)/test
	cd wasm && wasm-pack build --target web
	npm --prefix wasm/loader install
	npm --prefix wasm/loader run build
	rm -f $(TARGET)/test/asmjs.stamp
	touch $@ 

## WASM-ASM-JS

ASM_SRC=wasm/Cargo.toml wasm/asm/package.json wasm/asm/webpack.config.js wasm/asm/asm-loader.js $(WASM_SRC)

BINARYEN_ROOT="$(HOME)/binaryen"

$(TARGET)/test/asmjs.stamp: $(ASM_SRC) | $(TARGET)/test
	cd wasm && wasm-pack build --target bundler
	cd wasm/pkg && $(BINARYEN_ROOT)/bin/wasm2js --pedantic -o didkit_wasm_bg1.js didkit_wasm_bg.wasm
ifeq ($(OS_NAME),linux)
	sed -i '0,/didkit_wasm_bg.wasm/s//didkit_wasm_bg1.js/' wasm/pkg/didkit_wasm_bg.js
else
	sed -i '1,/didkit_wasm_bg.wasm/s//didkit_wasm_bg1.js/' wasm/pkg/didkit_wasm_bg.js
endif
	npm --prefix wasm/asm install
	npm --prefix wasm/asm run build
	rm -f $(TARGET)/test/wasm.stamp
	touch $@ 

## WASM-ASM-JS

BINARYEN_ROOT="$(HOME)/binaryen"

$(TARGET)/test/asmjs.stamp: $(WASM_SRC) | $(TARGET)/test
	cd wasm && wasm-pack build --target bundler
	cd wasm/pkg && $(BINARYEN_ROOT)/bin/wasm2js --pedantic -o didkit_wasm_bg1.js didkit_wasm_bg.wasm
	touch $@ 

## Cleanup

.PHONY: clean
clean:
	cargo clean
