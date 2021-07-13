#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint DIDKit.podspec' to validate before publishing.
#
Pod::Spec.new do |s|
    s.name             = 'DIDKit'
    s.version          = '0.2.1'
    s.summary          = 'DIDKit Swift Wrapper'
    s.description      = <<-DESC
    DIDKit Swift Wrapper
                         DESC
    s.homepage         = 'https://github.com/spruceid/didkit/lib/swift'
    s.license          = { :file => './LICENSE' }
    s.author           = { 'Spruce Systems, Inc.' => 'hello@spruceid.com' }
    s.source           = { :path => '.' }
    s.source_files = 'Sources/**/*'
    s.public_header_files = 'Sources/**/*.h'
    s.static_framework = true
    s.vendored_libraries = "**/*.a"
    s.platform = :ios, '11.0'

    # s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
    s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
    s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  end
  
