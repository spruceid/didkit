extern crate cbindgen;

use std::env;
use std::path::Path;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_dir = Path::new(&crate_dir).parent().unwrap();
    let workspace_dir = lib_dir.parent().unwrap();

    // Docs say to output into OUT_DIR, but then how do we use that?
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#outputs-of-the-build-script
    // https://stackoverflow.com/questions/63928113/is-there-a-way-to-change-out-dir-for-a-build-rs
    // let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = workspace_dir.join("target");
    let out_file = out_dir.join("didkit.h");

    cbindgen::generate(lib_dir)
        .expect("Unable to generate bindings")
        .write_to_file(&out_file);

    println!("cargo:rerun-if-changed={:?}", &out_file);
}
