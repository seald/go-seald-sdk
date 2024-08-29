#!/bin/bash -e

export BUILD_DIR="../build/windows"
export LIBRARY_FILENAME_BASE="lib_seald_sdk"

# Set common variables
export GOOS="windows"
export CGO_ENABLED=1

echo "Cleaning build dir..."
rm -rf ${BUILD_DIR}

echo "Building x86 (32-bit)..."
export GOARCH="386"
export CXX=i686-w64-mingw32-g++
export CC=i686-w64-mingw32-gcc
go build -buildmode=c-shared -o ${BUILD_DIR}/${LIBRARY_FILENAME_BASE}.x86.dll .

echo "Building AMD64 (x86_64)..."
export GOARCH="amd64"
export CXX=x86_64-w64-mingw32-g++
export CC=x86_64-w64-mingw32-gcc
go build -buildmode=c-shared -o ${BUILD_DIR}/${LIBRARY_FILENAME_BASE}.x86_64.dll .

echo "All done"
