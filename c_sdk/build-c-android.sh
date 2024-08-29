#!/bin/bash -e

export BUILD_DIR="../build/android-c"
export LIBRARY_FILENAME="lib_seald_sdk.so"
export ANDROID_API=21 # Choose the appropriate API level for your Android target

# Check if ANDROID_NDK is set
if [ -z "${ANDROID_NDK}" ]; then
    echo "Please set the ANDROID_NDK environment variable to the path of your installed Android NDK."
    exit 1
fi

# Determine the prebuilt directory based on the host platform
case "$(uname -s)" in
    Darwin*)    PREBUILT=darwin-x86_64;;
    Linux*)     PREBUILT=linux-x86_64;;
    *)          echo "Unknown platform. Please build manually."; exit 1;;
esac

# Set common variables
export GOOS="android"
export GOARM=7
export CGO_ENABLED=1

echo "Cleaning build dir..."
rm -rf ${BUILD_DIR}

echo "Building ARM..."
export GOARCH="arm"
export CC="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/armv7a-linux-androideabi${ANDROID_API}-clang"
export CXX="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/armv7a-linux-androideabi${ANDROID_API}-clang++"
go build -buildmode=c-shared -o ${BUILD_DIR}/jniLibs/armeabi-v7a/${LIBRARY_FILENAME} .

echo "Building ARM64..."
export GOARCH="arm64"
export CC="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/aarch64-linux-android${ANDROID_API}-clang"
export CXX="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/aarch64-linux-android${ANDROID_API}-clang++"
go build -buildmode=c-shared -o ${BUILD_DIR}/jniLibs/arm64-v8a/${LIBRARY_FILENAME} .

echo "Building x86 (32-bit)..."
export GOARCH="386"
export CC="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/i686-linux-android${ANDROID_API}-clang"
export CXX="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/i686-linux-android${ANDROID_API}-clang++"
go build -buildmode=c-shared -o ${BUILD_DIR}/jniLibs/x86/${LIBRARY_FILENAME} .

echo "Building AMD64 (x86_64)..."
export GOARCH="amd64"
export CC="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/x86_64-linux-android${ANDROID_API}-clang"
export CXX="${ANDROID_NDK}/toolchains/llvm/prebuilt/${PREBUILT}/bin/x86_64-linux-android${ANDROID_API}-clang++"
go build -buildmode=c-shared -o ${BUILD_DIR}/jniLibs/x86_64/${LIBRARY_FILENAME} .

echo "All done"
