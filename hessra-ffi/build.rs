use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Copy the header file to the output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let header_src = Path::new("include/hessra.h");
    let header_dst = Path::new(&out_dir).join("hessra.h");

    fs::copy(header_src, header_dst).expect("Failed to copy header file");

    // Tell cargo to invalidate the built crate whenever the header changes
    println!("cargo:rerun-if-changed=include/hessra.h");

    // Tell cargo to link with the C runtime
    println!("cargo:rustc-link-lib=dylib=c");
}
