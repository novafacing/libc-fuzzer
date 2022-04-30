/// ::crate-lib-name::path::to::item;
use ::libc_fuzzer::{extract_decls, FunctionDecl};
use clap::Parser;
use libafl_cc::{ClangWrapper, CompilerWrapper};
use log::{debug, error, info, warn};
use std::env::current_dir;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

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
        let libc = PathBuf::from("musl/install");
        let libc_inc = PathBuf::from("musl/install/include");
        let libc_lib = PathBuf::from("musl/install/lib");
        let cwd = current_dir().unwrap();
        let fdp_hdr_path = cwd.with_file_name("fuzzed_data_provider");
        let mut musl_ld_path = PathBuf::from(cwd.clone());
        musl_ld_path.push("musl/install/bin/ld.musl-clang");
        let mut cc = ClangWrapper::new();

        if let Some(code) = cc
            .cpp(true)
            .silence(true)
            .from_args(&vec![
                format!("-I{}", fdp_hdr_path.to_string_lossy().to_string()),
                format!("-L{}", libc_lib.to_string_lossy().to_string()),
                "-l:libmusl.a".to_string(),
                "-Wl,--allow-multiple-definition".to_string(),
            ])
            .expect("Failed to parse command line for compiler.")
            .link_staticlib(&cwd.join("target").join("debug"), "libc_fuzzer")
            .add_arg("-fsanitize-coverage=trace-pc-guard")
            .run()
            .expect("Failed to run compiler wrapper")
        {
            std::process::exit(code);
        }
    }

    Ok(())
}
