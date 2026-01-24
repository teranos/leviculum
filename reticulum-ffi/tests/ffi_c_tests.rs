//! Integration tests that compile and run C test programs
//!
//! These tests ensure the C API works correctly from actual C code.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Get the target directory where the library is built
fn get_target_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
}

/// Get the FFI crate directory
fn get_ffi_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
}

#[test]
fn test_c_identity_bindings() {
    let ffi_dir = get_ffi_dir();
    let target_dir = get_target_dir();

    let c_source = ffi_dir.join("c_tests").join("test_identity.c");
    let header_dir = &ffi_dir;
    let lib_dir = &target_dir;
    let output_binary = target_dir.join("test_identity_c");

    // Determine library name based on platform
    let lib_name = if cfg!(target_os = "windows") {
        "reticulum_ffi.dll"
    } else if cfg!(target_os = "macos") {
        "leviculum_ffi.dylib"
    } else {
        "leviculum_ffi.so"
    };

    let lib_path = lib_dir.join(lib_name);

    // Check that the library exists
    if !lib_path.exists() {
        panic!(
            "Library not found at {:?}. Run `cargo build -p reticulum-ffi` first.",
            lib_path
        );
    }

    // Compile the C test program
    let compile_status = Command::new("cc")
        .args([
            "-o",
            output_binary.to_str().unwrap(),
            c_source.to_str().unwrap(),
            "-I",
            header_dir.to_str().unwrap(),
            "-L",
            lib_dir.to_str().unwrap(),
            "-lreticulum_ffi",
            "-Wl,-rpath",
            lib_dir.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute cc compiler");

    if !compile_status.success() {
        panic!("Failed to compile C test program");
    }

    // Run the test program
    let output = Command::new(&output_binary)
        .env("LD_LIBRARY_PATH", lib_dir)
        .output()
        .expect("Failed to run C test program");

    // Print output for debugging
    println!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "C test program failed with exit code: {:?}",
        output.status.code()
    );
}
