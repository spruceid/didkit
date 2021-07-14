#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint DIDKit.podspec' to validate before publishing.
#
Pod::Spec.new do |s|
    s.name             = 'DIDKit'
    s.version          = '0.2.1'
    s.summary          = 'DIDKit Swift Wrapper'
    s.description      = <<-DESC
    DIDKit provides Verifiable Credential and Decentralized Identifier
    functionality across different platforms.
                         DESC
    s.homepage         = 'https://github.com/spruceid/didkit'
    s.license          = { :type => 'Apache 2.0', :file => './LICENSE' }
    s.author           = { 'Spruce Systems, Inc.' => 'hello@spruceid.com' }
    s.source           = { :http => 'https://github.com/spruceid/didkit/tree/feat/swift-native-lib/lib/swift' }
    s.source_files = 'lib/swift/Sources/**/*'
    s.public_header_files = 'lib/swift/Sources/**/*.h'
    s.static_framework = true
    s.vendored_libraries = "lib/swift/**/*.a"
    s.platform = :ios, '11.0'
    s.swift_versions = '5'

    # s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
    s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
    s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  end
  
