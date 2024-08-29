Pod::Spec.new do |s|
  s.name             = 'seald_sdk_flutter'
  s.version          = '0.0.1'
  s.summary          = 'Seald SDK C for Flutter'
  s.description      = <<-DESC
Seald SDK C, to be used by the Seald SDK for Flutter.
                       DESC
  s.homepage         = 'https://seald.io'
  s.license          = { :type => 'Seald license agreement', :text => 'See https://www.seald.io/licence-service-agreement-sdk' }
  s.author           = { 'SealdSAS' => 'contact@seald.io' }

  s.source           = { :path => '.' }
  # s.source           = { :http => 'https://download.seald.io/download/seald-sdk-c-ios/SealdSdkC-##PACKAGE_VERSION##.xcframework.tgz', :flatten => false } # flatten : https://github.com/CocoaPods/cocoapods-downloader/issues/95#issuecomment-582246021
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.vendored_frameworks = 'SealdSdkC.xcframework'

  s.ios.dependency 'Flutter'
  s.osx.dependency 'FlutterMacOS'
  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.11'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
