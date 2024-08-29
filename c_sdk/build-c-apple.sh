#!/bin/bash -e

# User variables
export FRAMEWORK_NAME="SealdSdkC"
export FRAMEWORK_ID="io.seald.sealdsdkc"
export FRAMEWORK_VERSION="0.1.0"
export ORIGINAL_HEADER_FILE="./seald_sdk.h"
export BUILD_DIR="../build/apple-c"
export IOS_MIN_VERSION="13.0"
export MACOS_MIN_VERSION="10.14"

# Set common variables
export XCODE_PATH=$(xcode-select -p)
export IOS_SDK_PATH="${XCODE_PATH}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
export IOS_SIMULATOR_SDK_PATH="${XCODE_PATH}/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
export MACOS_SDK_PATH="${XCODE_PATH}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
export CGO_ENABLED=1
export FRAMEWORK_IOS_PATH="${BUILD_DIR}/ios/${FRAMEWORK_NAME}.framework"
export FRAMEWORK_IOS_SIMULATOR_PATH="${BUILD_DIR}/ios-simulator/${FRAMEWORK_NAME}.framework"
export FRAMEWORK_MACOS_PATH="${BUILD_DIR}/macos/${FRAMEWORK_NAME}.framework"
export XCFRAMEWORK_PATH="${BUILD_DIR}/${FRAMEWORK_NAME}.xcframework"
export GOARM=7

echo "Cleaning build dir..."
rm -rf ${BUILD_DIR}

echo "Create the framework structure..."
mkdir -p "${FRAMEWORK_IOS_PATH}/Headers/" "${FRAMEWORK_IOS_PATH}/Modules/"
mkdir -p "${FRAMEWORK_IOS_SIMULATOR_PATH}/Headers/" "${FRAMEWORK_IOS_SIMULATOR_PATH}/Modules/"
mkdir -p "${FRAMEWORK_MACOS_PATH}/Headers/" "${FRAMEWORK_MACOS_PATH}/Modules/"

echo "Building iOS..."
export GOOS="ios"
export GOARCH="arm64"
export CC=$(xcrun --sdk iphoneos --find clang)
export CGO_CFLAGS="--sysroot=${IOS_SDK_PATH} -arch arm64 -mios-version-min=${IOS_MIN_VERSION}"
export CGO_LDFLAGS="--sysroot=${IOS_SDK_PATH} -arch arm64"
go build -buildmode=c-archive -tags=ios -o ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME}.a # have to use c-archive because go does not support c-shared on ios
xcrun -sdk iphoneos clang -arch arm64 -fPIC -dynamiclib -Wl,-all_load ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME}.a -framework Corefoundation -framework Security -install_name @rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME} -o ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME} -mios-version-min=${IOS_MIN_VERSION} # converting c-archive to c-shared https://stackoverflow.com/questions/62019384/build-a-c-shared-dylib-from-golang-for-ios-armv7-arm64
chmod -h +x ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME}
rm ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME}.a ${FRAMEWORK_IOS_PATH}/${FRAMEWORK_NAME}.h # cleanup
cp ${ORIGINAL_HEADER_FILE} ${FRAMEWORK_IOS_PATH}/Headers/${FRAMEWORK_NAME}.h # Copy the header file
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g; s/##FRAMEWORK_ID##/${FRAMEWORK_ID}/g; s/##FRAMEWORK_VERSION##/${FRAMEWORK_VERSION}/g; s/##OS_MIN_VERSION##/${IOS_MIN_VERSION}/g" Info-framework.plist > ${FRAMEWORK_IOS_PATH}/Info.plist # Copy Info.plist while setting values
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g" module.modulemap > ${FRAMEWORK_IOS_PATH}/Modules/module.modulemap # Copy module.modulemap while setting values

echo "Building iOS-simulator-arm..."
export GOOS="ios"
export GOARCH="arm64"
export TARGET="arm64-apple-ios${IOS_MIN_VERSION}-simulator"
export CC=$(xcrun --sdk iphonesimulator --find clang)
export CGO_CFLAGS="-target ${TARGET} --sysroot=${IOS_SIMULATOR_SDK_PATH} -arch arm64 -mios-simulator-version-min=${IOS_MIN_VERSION}"
export CGO_LDFLAGS="--target ${TARGET} --sysroot=${IOS_SIMULATOR_SDK_PATH} -arch arm64"
go build -buildmode=c-archive -tags=ios -o ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64.a # have to use c-archive because go does not support c-shared on ios
xcrun -sdk iphonesimulator clang -arch arm64 -fPIC -dynamiclib -Wl,-all_load ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64.a -framework Corefoundation -framework Security -install_name @rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME} -o ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64 -mios-simulator-version-min=${IOS_MIN_VERSION} # converting c-archive to c-shared https://stackoverflow.com/questions/62019384/build-a-c-shared-dylib-from-golang-for-ios-armv7-arm64
rm ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64.a ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64.h # cleanup

echo "Building iOS-simulator-x86..."
export GOOS="ios"
export GOARCH="amd64"
export TARGET="x86_64-apple-ios${IOS_MIN_VERSION}-simulator"
export CC=$(xcrun --sdk iphonesimulator --find clang)
export CGO_CFLAGS="-target ${TARGET} --sysroot=${IOS_SIMULATOR_SDK_PATH} -arch x86_64 -mios-simulator-version-min=${IOS_MIN_VERSION}"
export CGO_LDFLAGS="--target ${TARGET} --sysroot=${IOS_SIMULATOR_SDK_PATH} -arch x86_64"
go build -buildmode=c-archive -tags=ios -o ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64.a # have to use c-archive because go does not support c-shared on ios
xcrun -sdk iphonesimulator clang -arch x86_64 -fPIC -dynamiclib -Wl,-all_load ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64.a -framework Corefoundation -framework Security -install_name @rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME} -o ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64 -mios-simulator-version-min=${IOS_MIN_VERSION} # converting c-archive to c-shared https://stackoverflow.com/questions/62019384/build-a-c-shared-dylib-from-golang-for-ios-armv7-arm64
rm ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64.a ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64.h # cleanup

echo "Combining iOS-simulator-arm & iOS-simulator-x86..."
lipo -create -output ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME} ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64 ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64
chmod -h +x ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}
rm ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_arm64 ${FRAMEWORK_IOS_SIMULATOR_PATH}/${FRAMEWORK_NAME}_x86_64 # cleanup
cp ${ORIGINAL_HEADER_FILE} ${FRAMEWORK_IOS_SIMULATOR_PATH}/Headers/${FRAMEWORK_NAME}.h # Copy the header file
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g; s/##FRAMEWORK_ID##/${FRAMEWORK_ID}/g; s/##FRAMEWORK_VERSION##/${FRAMEWORK_VERSION}/g; s/##OS_MIN_VERSION##/${IOS_MIN_VERSION}/g" Info-framework.plist > ${FRAMEWORK_IOS_SIMULATOR_PATH}/Info.plist # Copy Info.plist while setting values
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g" module.modulemap > ${FRAMEWORK_IOS_SIMULATOR_PATH}/Modules/module.modulemap # Copy module.modulemap while setting values

echo "Building macOS-arm..."
export GOOS="darwin"
export GOARCH="arm64"
export CC=$(xcrun --sdk macosx --find clang)
export CGO_CFLAGS="--sysroot=${MACOS_SDK_PATH} -arch arm64 -mmacosx-version-min=${MACOS_MIN_VERSION}"
export CGO_LDFLAGS="--sysroot=${MACOS_SDK_PATH} -arch arm64 -extldflags \"-mmacosx-version-min=${MACOS_MIN_VERSION}\""
go build -buildmode=c-shared -o ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_arm64
install_name_tool -id @rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME} ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_arm64 # Need to use install_path to change the internal install_name of the library to point to the path within the framework that it is going to have
rm ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_arm64.h # cleanup

echo "Building macOS-x86..."
export GOOS="darwin"
export GOARCH="amd64"
export CC=$(xcrun --sdk macosx --find clang)
export CGO_CFLAGS="--sysroot=${MACOS_SDK_PATH} -arch x86_64 -mmacosx-version-min=${MACOS_MIN_VERSION}"
export CGO_LDFLAGS="--sysroot=${MACOS_SDK_PATH} -arch x86_64 -extldflags \"-mmacosx-version-min=${MACOS_MIN_VERSION}\""
go build -buildmode=c-shared -o ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_x86_64
install_name_tool -id @rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME} ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_x86_64 # Need to use install_path to change the internal install_name of the library to point to the path within the framework that it is going to have
rm ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_x86_64.h # cleanup

echo "Combining macOS-arm & macOS-x86..."
lipo -create -output ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME} ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_arm64 ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_x86_64
rm ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_arm64 ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}_x86_64 # cleanup
chmod -h +x ${FRAMEWORK_MACOS_PATH}/${FRAMEWORK_NAME}
cp ${ORIGINAL_HEADER_FILE} ${FRAMEWORK_MACOS_PATH}/Headers/${FRAMEWORK_NAME}.h # Copy the header file
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g; s/##FRAMEWORK_ID##/${FRAMEWORK_ID}/g; s/##FRAMEWORK_VERSION##/${FRAMEWORK_VERSION}/g; s/##OS_MIN_VERSION##/${MACOS_MIN_VERSION}/g" Info-framework.plist > ${FRAMEWORK_MACOS_PATH}/Info.plist # Copy Info.plist while setting values
sed "s/##FRAMEWORK_NAME##/${FRAMEWORK_NAME}/g" module.modulemap > ${FRAMEWORK_MACOS_PATH}/Modules/module.modulemap # Copy module.modulemap while setting values

# Create the XCFramework
echo "Linking into XCFramework..."
xcodebuild -create-xcframework \
    -framework ${FRAMEWORK_IOS_PATH} \
    -framework ${FRAMEWORK_IOS_SIMULATOR_PATH} \
    -framework ${FRAMEWORK_MACOS_PATH} \
    -output ${XCFRAMEWORK_PATH}

echo "All done"
