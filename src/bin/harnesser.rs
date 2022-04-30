/// ::crate-lib-name::path::to::item;
use ::libc_fuzzer::{extract_decls, FunctionDecl};
use clap::Parser;
use log::{debug, error, info, warn};
use std::env::current_dir;
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
    /* Default to info log level */
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = Args::parse();
    assert!(!args.functions.is_empty());
    let decls = extract_decls();
    info!("Found {} functions.", decls.len());

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

    for (funcname, proto, func) in to_fuzz
        .iter()
        .map(|f| -> (String, String, FunctionDecl) { (f.name.clone(), f.proto(), f.clone()) })
    {
        info!("Generating fuzzer for {}: {}", funcname, proto);
        let harness = func.harness();
        info!("Harness code:\n{}", harness.clone());

        /* Replicate the musl-clang script for afl-clang-lto++ also */
        let cwd = current_dir().unwrap();
        let libc_lib = cwd.join("musl/install/lib");
        let fdp_hdr_path = cwd.with_file_name("fuzzed_data_provider");
        let mut musl_ld_path = PathBuf::from(cwd.clone());
        let afl_ld_lto =
            which("afl-ld-lto").expect("Ensure `afl-ld-lto` is installed and is found in $PATH!");
        musl_ld_path.push("musl/install/bin/ld.musl-clang");

        Command::new("afl-clang-lto++")
            .arg("-I")
            .arg(fdp_hdr_path.to_string_lossy().to_string())
            .arg("-L")
            .arg(libc_lib.to_string_lossy().to_string())
            .arg("-l:libmusl.a")
            .arg("-Wl,--allow-multiple-definition")
            // .arg("-stdlib=libc++")
            .arg("-fsanitize-coverage=trace-pc-guard")
            .arg("-L")
            .arg(&cwd.join("target").join("debug"))
            .arg("-l:liblibc_fuzzer.a")
            .arg("-g")
            .arg("-O3")
            .arg("-funroll-loops")
            .arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1")
            .arg("-v")
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .current_dir(cwd)
            .status()
            .expect("Failed to compile.");
    }

    Ok(())
}
