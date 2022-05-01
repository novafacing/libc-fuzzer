/// ::crate-lib-name::path::to::item;
use ::libc_fuzzer::{extract_decls, FunctionDecl};
use clap::Parser;
use log::{error, info, warn};
use std::env::current_dir;
use std::fs::write;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::process::Command;
use which::which;

// libc fuzzer generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // List of libc functions to fuzz
    functions: Vec<String>,
}

fn main() -> Result<(), Error> {
    // Default to info log level
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Extract musl libc header declarations
    let args = Args::parse();
    assert!(!args.functions.is_empty());
    let decls = extract_decls();
    info!("Found {} functions.", decls.len());

    // Figure out what functions the user wants to fuzz, which ones are missing, and sanity check
    let to_fuzz: Vec<FunctionDecl> = decls
        .into_iter()
        .filter(|f| -> bool { args.functions.contains(&f.name) })
        .collect();

    let missing: Vec<String> = args
        .functions
        .into_iter()
        .filter(|f| -> bool {
            to_fuzz
                .clone()
                .into_iter()
                .filter(|tf| -> bool { tf.name == f.as_str() })
                .count()
                == 0
        })
        .collect();

    for funcname in missing {
        warn!(
            "Missing function {}, not generating a fuzzer for it.",
            funcname
        );
    }

    if to_fuzz.is_empty() {
        error!("No functions to fuzz!");
        return Err(Error::new(ErrorKind::Other, "No functions to fuzz!"));
    }

    // Generate harnesses and compile them
    for (funcname, proto, func) in to_fuzz
        .iter()
        .map(|f| -> (String, String, FunctionDecl) { (f.name.clone(), f.proto(), f.clone()) })
    {
        info!("Generating fuzzer for {}: {}", funcname, proto);
        let fuzz_harness = func.harness("template.cc".to_string());
        let manual_harness = func.harness("template_manual.cc".to_string());
        info!("Harness code:\n{}", fuzz_harness.clone());

        write(format!("harness-{}.cc", funcname), fuzz_harness)
            .expect("Could not write harness file.");
        write(format!("harness-{}-manual.cc", funcname), manual_harness)
            .expect("Could not write harness file.");

        /* Replicate the musl-clang script for afl-clang-lto++ also */
        let cwd = current_dir().unwrap();
        let libcpp_include = PathBuf::from("/usr/lib/llvm-14/include/c++/v1");
        let libcpp_lib = PathBuf::from("/usr/lib/llvm-14/lib");
        let fdp_hdr_path = cwd.join("fuzzed_data_provider");

        Command::new("afl-clang-fast++")
            .arg("-I")
            .arg(fdp_hdr_path.to_string_lossy().to_string())
            .arg("-I")
            .arg(libcpp_include.to_string_lossy().to_string())
            .arg("-L")
            .arg(libcpp_lib.to_string_lossy().to_string())
            .arg("-stdlib=libc++")
            .arg("-D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE")
            // .arg("--sysroot")
            // .arg(sysroot.to_string_lossy().to_string())
            .arg("-g")
            .arg("-O0")
            // .arg("-O3")
            // .arg("-funroll-loops")
            .arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1")
            .arg("-o")
            .arg(format!("fuzzer-{}", funcname))
            .arg(format!("harness-{}.cc", funcname))
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .env("CC", which("clang-14").expect("clang-14 is not installed."))
            .env(
                "CXX",
                which("clang++-14").expect("clang++-14 is not installed."),
            )
            .current_dir(cwd.clone())
            .status()
            .expect("Could not compile harness.");

        Command::new("clang++")
            .arg("-I")
            .arg(fdp_hdr_path.to_string_lossy().to_string())
            .arg("-I")
            .arg(libcpp_include.to_string_lossy().to_string())
            .arg("-L")
            .arg(libcpp_lib.to_string_lossy().to_string())
            .arg("-stdlib=libc++")
            .arg("-D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE")
            // .arg("--sysroot")
            // .arg(sysroot.to_string_lossy().to_string())
            .arg("-g")
            .arg("-O0")
            // .arg("-O3")
            // .arg("-funroll-loops")
            .arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1")
            .arg("-o")
            .arg(format!("fuzzer-{}-manual", funcname))
            .arg(format!("harness-{}-manual.cc", funcname))
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .env("CC", which("clang-14").expect("clang-14 is not installed."))
            .env(
                "CXX",
                which("clang++-14").expect("clang++-14 is not installed."),
            )
            .current_dir(cwd.clone())
            .status()
            .expect("Could not compile harness.");
    }

    Ok(())
}
