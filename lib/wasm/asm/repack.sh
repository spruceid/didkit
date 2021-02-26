cat didkit_wasm_bg.js | \
  sed -e 's/export const __wb/const __wb/' | \
  tail -n +3 | \
  cat >> didkit-output.js

echo 'const wasm = {};' >> didkit-output.js

cat didkit_wasm_bg1.js | \
  sed -e "/^import { __wb.*} from '\.\/didkit_wasm_bg\.js';$/d" | \
  sed -e "s/export var /wasm./" | \
  cat >> didkit-output.js
