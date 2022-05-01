use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use which::which;

fn main() -> Result<(), io::Error> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=musl/");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rustc-link-arg=-Wl,--allow-multiple-definition");

    /* Build musl-libc  */

    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let musl_dir = format!("{}/musl", cwd);
    let musl_output_dir = format!("{}/musl/install", cwd);

    let afl_clang_fast = which("afl-clang-fast")
        .expect("Ensure `afl-clang-fast` is installed and is found in $PATH!");
    let afl_clangpp_fast = which("afl-clang-fast++")
        .expect("Ensure `afl-clang-fast++` is installed and is found in $PATH!");
    let afl_ld_fast = which("lld-14").expect("Ensure `lld-14` is installed and is found in $PATH!");
    let llvm_config_14 = which("llvm-config-14")
        .expect("Ensure `llvm-config-14` is installed and is found in $PATH");

    /* Build tree-sitter */
    let tree_sitter_dir: PathBuf = PathBuf::from("third_party/tree-sitter-c/src");

    cc::Build::new()
        .warnings(false)
        .include(&tree_sitter_dir)
        .file(tree_sitter_dir.join("parser.c"))
        .compile("tree-sitter-c");

    println!("cargo:rustc-link-lib=static=tree-sitter");
    // println!("cargo:rustc-link-search=native={}", cwd);

    /* Delete the existing musl libc directory if one exists */
    if !Path::new(&musl_dir).is_dir() {
        /* Clone a fresh musl libc directory */
        Command::new("git")
            .arg("clone")
            // .arg("-b")
            // .arg("v1.2.3")
            // .arg("git://git.musl-libc.org/musl")
            .arg("https://github.com/novafacing/libmusl.git")
            .arg("musl")
            .current_dir(cwd.clone())
            .status()
            .expect("Could not clone musl-libc.");
    }

    if !Path::new(&musl_output_dir).is_dir() {
        /* Configure musl libc with clang */
        Command::new("./configure")
            .arg(&format!("--prefix={}/install", musl_dir.clone()))
            .arg("--disable-shared")
            .env("LLVM_CONFIG", llvm_config_14.clone())
            .env("CC", afl_clang_fast.clone())
            .env("CXX", afl_clangpp_fast.clone())
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .env("LD", afl_ld_fast.clone())
            // .env("AFL_LLVM_LAF_ALL", "1")
            // .env("AFL_USE_ASAN", "1")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't configure musl-libc using afl-clang-fast.");

        Command::new("make")
            .env("LLVM_CONFIG", llvm_config_14.clone())
            .env("CC", afl_clang_fast.clone())
            .env("CXX", afl_clangpp_fast.clone())
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .env("LD", afl_ld_fast.clone())
            // .env("AFL_LLVM_LAF_ALL", "1")
            // .env("AFL_USE_ASAN", "1")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't build musl-libc using afl-clang-fast.");

        Command::new("make")
            .arg("install")
            .current_dir(musl_dir.clone())
            .status()
            .expect("Couldn't install musl-libc.");
    }

    Ok(())
}
