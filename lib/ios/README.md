# DIDKit Swift Wrapper

A _swifty_ wrapper for the DIDKit C interface.

## Build and Install

DIDKit for iOS supports the cocoapods dependency manager through path dependency.

Run the following for building didkit static library.

```sh
$ make -C ../ install-rustup-ios
$ make -C ../ ../target/test/ios.stamp
```

On your `Podfile` add: 

```ruby
pod 'DIDKit', :path => 'path/to/local/didkit'
```

See [Example](Example) on how to integrate DIDKit on your Xcode project.