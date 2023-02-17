import * as wasm from "./didkit_wasm_bg.wasm";
import { __wbg_set_wasm } from "./didkit_wasm_bg.js";
__wbg_set_wasm(wasm);
export * from "./didkit_wasm_bg.js";
