import svelte from "rollup-plugin-svelte";
import commonjs from "@rollup/plugin-commonjs";
import { nodeResolve } from '@rollup/plugin-node-resolve';
import copy from 'rollup-plugin-copy';
import typescript from "@rollup/plugin-typescript";
import livereload from "rollup-plugin-livereload";
import { terser } from "rollup-plugin-terser";
import sveltePreprocess from "svelte-preprocess";
import { wasm } from '@rollup/plugin-wasm';
import styles from "rollup-plugin-styles";
import nodePolyfills from 'rollup-plugin-polyfill-node';

const production = !process.env.ROLLUP_WATCH;

function serve() {
  let server;

  function toExit() {
    if (server) server.kill(0);
  }

  return {
    writeBundle() {
      if (server) return;
      server = require("child_process").spawn("npm", ["run", "start", "--", "--dev"], {
        stdio: ["ignore", "inherit", "inherit"],
        shell: true
      });

      process.on("SIGTERM", toExit);
      process.on("exit", toExit);
    }
  };
}

export default {
  input: "src/main.ts",
  output: {
    sourcemap: !production,
    name: "app",
    file: "public/build/bundle.js"
  },
  plugins: [
    svelte({
      preprocess: sveltePreprocess({
        postcss: {
          plugins: [
            require("tailwindcss"),
            require("autoprefixer")
          ]
        }
      }),
      compilerOptions: {
        dev: !production
      }
    }),
    typescript({
      sourceMap: !production,
      inlineSources: !production
    }),
    copy({
      targets: [{
        src: 'node_modules/didkit-wasm/didkit_wasm_bg.wasm',
        dest: 'public/build',
        rename: 'didkit_wasm_bg.wasm'
      }]
    }),
    wasm(),
    commonjs(),
    nodePolyfills(),
    nodeResolve({
    }),
    styles(),
    !production && serve(),
    !production && livereload("public"),
    production && terser()
  ],
  watch: {
    clearScreen: false
  }
};
