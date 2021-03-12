# VC HTTP API DIDKit HTTP test runner

Runs the [VC HTTP API Test Server][vc-http-api-test-server] with a local instance of [DIDKit][didkit-http].

## Install

Requirements: [git][], [Cargo][] and [Node.js][].

`didkit` and `ssi` should be checked out:
```sh
git clone https://github.com/spruceid/didkit
git clone https://github.com/spruceid/ssi --recurse-submodules
```

Checkout the `vc-http-api` test server:
```sh
cd didkit/http/tests/vc-http-api
git clone https://github.com/w3c-ccg/vc-http-api --depth 1
```

Install `npm` dependencies:
```sh
npm install
```

## Usage

Run the test suite:
```sh
npm test
```

`didkit-http` will automatically build and run on a random port for the duration of the tests. The test suite will issue requests to the `didkit-http` instance.

[git]: https://git-scm.com/
[vc-http-api-test-server]: https://github.com/w3c-ccg/vc-http-api/tree/df9d1bf9540771d114f5b4c4348777378a3f0447/packages/vc-http-api-test-server
[didkit-http]: ../../
[Cargo]: https://doc.rust-lang.org/cargo/
[Node.js]: https://nodejs.org/
