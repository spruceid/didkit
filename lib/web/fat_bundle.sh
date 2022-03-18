#!/usr/bin/env bash
set -e

PKG_NAME="didkit_wasm"
PKG_DIR="fat_pkg"

if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed" >& 2
    exit 1
fi

rm -rf ./ts
mkdir -p ./ts

wasm-pack build  --out-dir $PKG_DIR/web
wasm-pack build  --target nodejs --out-dir $PKG_DIR/node

mv $PKG_DIR/web/package.json $PKG_DIR/
rm $PKG_DIR/node/package.json

# set the package.json main key (affects how nodejs loads this)
cat $PKG_DIR/package.json | jq --arg main "node/$PKG_NAME.js" '.main = $main'> TMP_FILE && mv TMP_FILE $PKG_DIR/package.json

# set the package.json browser key (affects how bundlers load this)
cat $PKG_DIR/package.json | jq --arg browser "web/$PKG_NAME.js" '.browser = $browser'> TMP_FILE && mv TMP_FILE $PKG_DIR/package.json

# set the package.json module key (affects how bundlers load this)
cat $PKG_DIR/package.json | jq --arg m "web/$PKG_NAME.js" '.module = $m' > TMP_FILE && mv TMP_FILE $PKG_DIR/package.json

# set the package.json types key
cat $PKG_DIR/package.json | jq --arg types "web/$PKG_NAME.d.ts" '.types = $types' > TMP_FILE && mv TMP_FILE $PKG_DIR/package.json

# empty the package.json files list
cat $PKG_DIR/package.json | jq '.files = []' > TMP_FILE && mv TMP_FILE $PKG_DIR/package.json

# add each web file to the package.json files list
for F in "web/$PKG_NAME""_bg.wasm" "web/$PKG_NAME""_bg..d.ts" "web/$PKG_NAME.js" "web/$PKG_NAME.d.ts" "web/$PKG_NAME""_bg.js"
do
    cat $PKG_DIR/package.json | jq --arg f "$F" '.files += [$f]' > TMP_FILE && mv TMP_FILE $PKG_DIR/package.json
done

# add each node file to the package.json files list
for F in "node/$PKG_NAME""_bg.wasm" "node/$PKG_NAME""_bg.d.ts" "node/$PKG_NAME.js" "node/$PKG_NAME.d.ts"
do
    cat $PKG_DIR/package.json | jq --arg f "$F" '.files += [$f]' > TMP_FILE && mv TMP_FILE $PKG_DIR/package.json
done

sed -i 's/"didkit-wasm"/"@spruceid\/didkit-wasm"/g' $PKG_DIR/package.json
