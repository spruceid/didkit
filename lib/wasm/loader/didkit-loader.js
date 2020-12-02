/* global window */
"use strict";

import init, * as DIDKit from "../pkg/didkit_wasm.js";

let loaded;
export async function loadDIDKit(url = "/didkit/didkit_wasm_bg.wasm") {
  if (loaded) return DIDKit;
  loaded = true;
  await init(url);
  window.DIDKit = DIDKit;
  return DIDKit;
}
