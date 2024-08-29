part of 'seald_sdk.dart';

/// The dynamic library in which the symbols for [FlutterSealdSdkFfiBindings] can be found.
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    return DynamicLibrary.open('lib_seald_sdk.so');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

/// The bindings to the native functions in [_dylib].
final SealdSdkCBindings _bindings = SealdSdkCBindings(_dylib);
