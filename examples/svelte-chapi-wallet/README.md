# Svelte Demo CHAPI Wallet

This project aims to demonstrate how one could implement a CHAPI conformant 
Wallet using [`DIDKit`](https://github.com/spruceid/didkit).

## Dependencies

To be able to run this example, you will need to build `DIDKit` for the WASM
target. More instructions about the process can be found
[here](https://github.com/spruceid/didkit/tree/main/lib/wasm). You will also
need Node.js/NPM.

### `DIDKit`

In short, you need to install the `wasm-unknown-unknown` Rust target and
`wasm-pack`, which can be done with the following command on the root of
`DIDKit`:

```bash
$ make -C lib install-wasm-pack
```

#### Building

Then, you have to build the WASM target of `DIDKit`:

```bash
$ make -C lib ../target/test/wasm.stamp
```

If everything succeeds, you can proceed to the next step.

## Running

Install the `npm` dependencies of this example project using
[Yarn](https://yarnpkg.com/) with:

```bash
$ cd examples/svelte-chapi-wallet
$ yarn install
```

The run the app in development mode with:

```bash
$ yarn run dev
```

You should now be able to see the app running on
[localhost:5000](http://localhost:5000).

## Building and running in production mode

To create an optimised version of the app:

```bash
$ yarn run build
```

You can run the newly built app with `yarn run start`. This uses
[sirv](https://github.com/lukeed/sirv), which is included in your
package.json's `dependencies` so the app will function when deployed to
platforms such as [Heroku](https://heroku.com).
