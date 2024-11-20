# iOS Wrapper

## Build `SealdSdkInternals.xcframework` from Go

To simply build the XCFramework:

```bash
# From the root:
mkdir -p ./ios_wrapper/SealdSdk/Frameworks/
gomobile bind -target=ios -prefix=SealdSdkInternals -v -o=./ios_wrapper/SealdSdk/Frameworks/SealdSdkInternals.xcframework ./mobile_sdk
```

## Lint

### Linting Objective-C code

For Objective-C code (the iOS SDK Wrapper + the ObjC example), linting uses [`uncrustify`](https://github.com/uncrustify/uncrustify).

Linting rules are defined in `uncrustify.cfg` in the root directory. Configuration is shared.

To install `uncrustify`, use `brew` on macos (`brew install uncrustify`), or your package manager on linux.

To verify formatting, you can run `uncrustify -c ../uncrustify.cfg --check -l OC ./SealdSdk/Classes/*.h ./SealdSdk/Classes/*.m` in the `ios_wrapper` directory.

To fix formatting, you can run `uncrustify -c ../uncrustify.cfg --no-backup -l OC ./SealdSdk/Classes/*.h ./SealdSdk/Classes/*.m`.

### Linting Swift code

For Swift code (the Swift example), linting uses [`SwiftLint`](https://github.com/realm/SwiftLint).

To install, simply run `brew install swiftlint`.

To verify formatting, you can run `swiftlint lint` in the `ios_wrapper/example_swift/` folder.

To fix formatting, you can run `swiftlint lint --fix` in the `ios_wrapper/example_swift/` folder.

## Using the local version in a project

You can use the local version in a project instead of one from a repo, by using the following line in its Podfile:

```ruby
  pod 'SealdSdk', :path => 'LOCAL_PATH/go-seald-sdk/ios_wrapper'
```
