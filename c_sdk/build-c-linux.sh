#!/bin/bash -e

export BUILD_DIR="../build/linux"
export LIBRARY_FILENAME_BASE="lib_seald_sdk"

# Set common variables
export GOOS="linux"
export CGO_ENABLED=1

echo "Cleaning build dir..."
rm -rf ${BUILD_DIR}

echo "Building x86 (32-bit)..." # Requires to install `glibc-devel.i686` (on Fedora at least)
export GOARCH="386"
export CXX="g++ -m32"
export CC="gcc -m32"
go build -buildmode=c-shared -o ${BUILD_DIR}/${LIBRARY_FILENAME_BASE}.x86.so .

echo "Building AMD64 (x86_64)..."
export GOARCH="amd64"
export CXX="g++ -m64"
export CC="gcc -m64"
go build -buildmode=c-shared -o ${BUILD_DIR}/${LIBRARY_FILENAME_BASE}.x86_64.so .

echo "All done"
