# Gin Example

This project demonstrates use of verifiable credentials and presentation  for an
application.

## Dependencies

- Rust ([installation instructions](https://www.rust-lang.org/tools/install))
- Golang 1.6

### Building DIDKit
From this folder run the following command:

```bash
$ make -C ../../lib ../target/test/c.stamp
```

## Running

For the first time running you will need to install de dependencies:

```bash
$ go get .
```

And update the library path

```bash
$ go mod edit -replace=github.com/spruceid/didkit-go=../../lib/didkit-go
```
