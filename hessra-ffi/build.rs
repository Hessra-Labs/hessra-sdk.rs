extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let package_name = env::var("CARGO_PKG_NAME").unwrap().replace('-', "_");
    let output_file = PathBuf::from(&crate_dir).join(format!("{}.h", package_name)); // Will generate e.g., hessra_ffi.h

    // Use a cbindgen.toml file for configuration if it exists
    let config_file = PathBuf::from(&crate_dir).join("cbindgen.toml");
    let config = if config_file.exists() {
        cbindgen::Config::from_file(config_file).expect("Failed to load cbindgen.toml")
    } else {
        // Default configuration if no cbindgen.toml
        cbindgen::Config {
            language: cbindgen::Language::C,
            // Add other default configurations here if needed, e.g.:
            // header: Some(format!("/* Generated header for {} */", package_name)),
            ..Default::default()
        }
    };

    cbindgen::generate_with_config(&crate_dir, config)
        .expect("Unable to generate C bindings")
        .write_to_file(&output_file);

    println!("cargo:rerun-if-changed=cbindgen.toml");
    // Use the generated output file path for rerun-if-changed
    println!("cargo:rerun-if-changed={}", output_file.display());
}
