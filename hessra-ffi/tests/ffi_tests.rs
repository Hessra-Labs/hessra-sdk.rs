#[test]
fn test_c_example_compiles_and_runs() {
    // This test compiles and runs the C example code to ensure it works correctly

    // First, build the library
    let output = std::process::Command::new("cargo")
        .args(["build"])
        .output()
        .expect("Failed to build library");

    assert!(
        output.status.success(),
        "Failed to build library: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Get the directory of the compiled library
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let debug_dir = format!("{}/target/debug", manifest_dir.replace("/hessra-ffi", ""));

    // Compile the C example
    let gcc_output = std::process::Command::new("gcc")
        .args([
            "-o",
            &format!("{}/test_example", debug_dir),
            &format!("{}/examples/test.c", manifest_dir),
            "-L",
            &debug_dir,
            "-lhessra",
            "-I",
            &format!("{}/include", manifest_dir),
        ])
        .output()
        .expect("Failed to compile C example");

    assert!(
        gcc_output.status.success(),
        "Failed to compile C example: {}",
        String::from_utf8_lossy(&gcc_output.stderr)
    );

    // Run the example with the appropriate library path
    #[cfg(target_os = "linux")]
    let lib_env = "LD_LIBRARY_PATH";
    #[cfg(target_os = "macos")]
    let lib_env = "DYLD_LIBRARY_PATH";
    #[cfg(target_os = "windows")]
    let lib_env = "PATH";

    let run_output = std::process::Command::new(&format!("{}/test_example", debug_dir))
        .env(lib_env, &debug_dir)
        .output()
        .expect("Failed to run C example");

    assert!(
        run_output.status.success(),
        "C example failed to run: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    println!(
        "C example output: {}",
        String::from_utf8_lossy(&run_output.stdout)
    );
}
