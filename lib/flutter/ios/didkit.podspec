#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint didkit.podspec' to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'didkit'
  s.version          = '0.0.1'
  s.summary          = 'DIDKit Flutter plugin - iOS implementation'
  s.description      = <<-DESC
DIDKit Flutter plugin - iOS implementation
                       DESC
  s.homepage         = 'https://github.com/spruceid/didkit/tree/main/lib/flutter'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Spruce Systems, Inc.' => 'hello@spruceid.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.static_framework = true
  s.vendored_libraries = "**/*.a"
  s.dependency 'Flutter'
  s.platform = :ios, '11.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
