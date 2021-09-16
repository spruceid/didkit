# Manual Tests in the Browser

Install your favourite local server:
```bash
$ cargo install https
```

```bash
$ cd .. && wasm-pack build --target web --out-dir pkg/web & cd test
$ http
```

You can now open [http://127.0.0.1:8000](http://127.0.0.1:8000).
