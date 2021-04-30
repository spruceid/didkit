# MacOS
### References were taken from [this](https://wapl.es/rust/2019/02/17/rust-cross-compile-linux-to-macos.html) article.

Dependencies and cross-compiler:
```bash
$ sudo apt install clang cmake git patch libssl-dev lzma-dev \ 
		gcc g++ zlib1g-dev libmpc-dev libmpfr-dev \ 
		libgmp-dev libxml2-dev
$ rustup target add x86_64-apple-darwin
$ git clone https://github.com/tpoechtrager/osxcross
$ cd osxcross
$ wget -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz
$ mv MacOSX10.10.sdk.tar.xz tarballs/
```


Make sure to have CMake >= 3.2.3:
```bash
$ UNATTENDED=yes OSX_VERSION_MIN=10.7 ./build.sh
```

Add `osxcross/target/bin` to your `$PATH`, replace `$OSX_CROSS_LOCATION` with 
the path of your instalation.
```bash
    export PATH="$PATH:$OSX_CROSS_LOCATION/target/bin"
```

Add to `~/.cargo/config`
```toml
[target.x86_64-apple-darwin]
  linker = "x86_64-apple-darwin14-clang"
  ar = "x86_64-apple-darwin14-ar"
```

Compile with:
```bash
$ CC=o64-clang \
  CXX=o64-clang++ \
  MACOSX_DEPLOYMENT_TARGET=10.7 \
  cargo build --lib --release \
    --target x86_64-apple-darwin
```

## Known issues
I can't run the build script from `osxcross`:

 - Make sure to have CMake >= 3.2.3

My compilation is failing with:
```
was built for newer macOS version (10.7) than being linked (10.6)
```
 - Change the `MACOSX_DEPLOYMENT_TARGET` flag to the correct version of your
  osxcross

# Windows
Dependencies and cross-compiler:
```bash
$ sudo apt install mingw-w64
$ rustup target add x86_64-pc-windows-gnu
```

Compile with:
```bash
$ CC=x86_64-w64-mingw32-gcc \
  CXX=x86_64-w64-mingw32-g++ \
  cargo build --lib --release \
    --target x86_64-pc-windows-gnu
```
