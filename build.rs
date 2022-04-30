use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use which::which;

fn main() -> Result<(), io::Error> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=musl/");
    println!("cargo:rerun-if-changed=src/main.rs");

    /* Build tree-sitter */
    let tree_sitter_dir: PathBuf = PathBuf::from("third_party/tree-sitter-c/src");

    cc::Build::new()
        .include(&tree_sitter_dir)
        .file(tree_sitter_dir.join("parser.c"))
        .compile("tree-sitter-c");

    /* Build musl-libc  */

    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let musl_dir = format!("{}/musl", cwd);
    let musl_output_dir = format!("{}/musl/install", cwd);

    let afl_clang_lto =
        which("afl-clang-lto").expect("Ensure `afl-clang-lto` is installed and is found in $PATH!");
    let afl_clangpp_lto = which("afl-clang-lto++")
        .expect("Ensure `afl-clang-lto++` is installed and is found in $PATH!");
    let afl_ld_lto =
        which("afl-ld-lto").expect("Ensure `afl-ld-lto` is installed and is found in $PATH!");

    /* Delete the existing musl libc directory if one exists */
    if !Path::new(&musl_dir).is_dir() {
        /* Clone a fresh musl libc directory */
        Command::new("git")
            .arg("clone")
            .arg("-b")
            .arg("v1.2.3")
            .arg("git://git.musl-libc.org/musl")
            .current_dir(cwd.clone())
            .status()
            .expect("Could not clone musl-libc.");
    }

    if !Path::new(&musl_output_dir).is_dir() {
        /* Configure musl libc with clang */
        Command::new("./configure")
            .arg(&format!("--prefix={}/install", musl_dir.clone()))
            .arg("--disable-shared")
            .env("CC", afl_clang_lto.clone())
            .env("CXX", afl_clangpp_lto.clone())
            .env("AR", "llvm-ar-13")
            .env("RANLIB", "llvm-ranlib-13")
            .env("LD", afl_ld_lto.clone())
            .env("AFL_LLVM_LAF_ALL", "1")
            .env("AFL_USE_ASAN", "1")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't configure musl-libc using afl-clang-lto.");

        Command::new("make")
            .env("CC", afl_clang_lto.clone())
            .env("CXX", afl_clangpp_lto.clone())
            .env("AR", "llvm-ar-13")
            .env("RANLIB", "llvm-ranlib-13")
            .env("LD", afl_ld_lto.clone())
            .env("AFL_LLVM_LAF_ALL", "1")
            .env("AFL_USE_ASAN", "1")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't build musl-libc using afl-clang-lto.");

        Command::new("make")
            .arg("install")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't install musl-libc.");
    }

    Ok(())
}
