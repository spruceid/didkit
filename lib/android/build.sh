#!/usr/bin/bash

export ANDROID_SDK_ROOT=~/Android/Sdk
make -C ../ ../target/test/android.stamp
./gradlew :didkit:publishToMavenLocal
