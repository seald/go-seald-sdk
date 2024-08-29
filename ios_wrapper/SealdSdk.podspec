Pod::Spec.new do |s|
  s.name             = 'SealdSdk'
  s.version          = ENV['CI_COMMIT_TAG'] ? ENV['CI_COMMIT_TAG'].gsub(/^v/, '') : (ENV['CI_PIPELINE_ID'] ? "0.1.0-beta.#{ENV['CI_PIPELINE_ID']}" : "0.0.1-local")
  s.summary          = 'Simple End-to-End encryption SDK.'

  s.description      = <<-DESC
Seald is an encryption SDK that allows you to use state-of-the-art End-to-End encryption without any cryptography expertise.
                       DESC

  s.homepage         = 'https://seald.io'
  s.license          = { :type => 'Seald license agreement', :text => 'See https://www.seald.io/licence-service-agreement-sdk' }
  s.author           = { 'SealdSAS' => 'contact@seald.io' }
  s.source           = { :http => "https://download.seald.io/download/seald-sdk-ios/SealdSdk-#{ENV['PACKAGE_VERSION']}.tgz", :flatten => false } # flatten : https://github.com/CocoaPods/cocoapods-downloader/issues/95#issuecomment-582246021

  s.ios.deployment_target = '13.0'
  s.ios.vendored_frameworks = 'SealdSdk/Frameworks/SealdSdkInternals.xcframework'
  s.source_files = 'SealdSdk/Classes/**/*'
end
