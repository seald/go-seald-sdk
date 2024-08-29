## prerequisite

Install `dart` & `flutter`

To compile on linux, you must also install these packages: `llvm`, `libclang-dev`.

## Copy libraries

```bash
# First, you must build C libraries (see `c_sdk/README_DEV.md`)

# From the `flutter_wrapper` directory:

# Copy Android C-sdk library
mkdir -p ./android/src/main/ && cp -r ../build/android-c/jniLibs ./android/src/main/
# Copy iOS/macOS C-sdk library
cp -r ../build/apple-c/SealdSdkC.xcframework ./darwin/
# Copy C headers
mkdir -p ./c-headers && cp ../c_sdk/seald_sdk.h ./c-headers/
# Generate C bindings
dart run ffigen --config ffigen.yaml
```

## Lint

To check if the linting is correct:
```bash
dart format --output=none --set-exit-if-changed .
```

To fix the linting:
```bash
dart format .
```

To analyze code (checks for unknown variables, unused imports, ...):
```bash
dart analyze --fatal-infos
```

## Run the app

```bash
 # Install dependencies
flutter pub get

cd example

# To run on iOS, you may need to go into the `ios` folder and run `pod install`
# To run on macOS go to the `macos` folder and run `pod install`

# Before this, you must start an emulator or connect a device

# To run on the first available device
flutter run

# To run un a specific device
flutter devices
# Copy the device ID (second column), then
flutter run -d DEVICE_ID
```
