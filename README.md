DIDKitのnpmパッケージのバージョンが古いので、新しいバージョンでビルドしたものを使えるようにするためのリポジトリ

https://github.com/spruceid/didkit/pkgs/npm/didkit

https://www.npmjs.com/package/@spruceid/didkit-wasm

## build
```
sh build.sh
```
`didkit-wasm-node`, `didkit-wasm` ディレクトリの中にbuildの成果物が出力される。

それぞれ、`.gitignore`も出力されるので削除して、成果物をpushする。

## 使用例
```json
"dependencies": {
  "@pitpa/didkit": "https://github.com/pitpa/didkit.git"
}
```

```js
import { verifyCredential } from "@pitpa/didkit/didkit-wasm-node"
import { issueCredential } from "@pitpa/didkit/didkit-wasm"
```
