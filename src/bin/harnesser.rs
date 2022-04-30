use clap::Parser;
use libafl_cc::{ClangWrapper, CompilerWrapper};
use log::{debug, error, info, warn};
use rust_embed::RustEmbed;
use std::env::current_dir;
use std::fs::{read_dir, read_to_string};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser as TParser, Query, QueryCursor};

// libc fuzzer generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // List of libc functions to fuzz
    functions: Vec<String>,
}

#[derive(RustEmbed)]
#[folder = "fuzzed_data_provider"]
struct CCAsset;

/* Check if a type is probably an input...
 * #TODO: Make this better
 */
fn is_input(params: Vec<String>) -> bool {
    if params.contains(&"*".to_string()) {
        return params.contains(&"const".to_string());
    } else {
        return true;
    }
}

#[derive(Clone)]
struct FunctionDecl {
    ty: Vec<String>,
    name: String,
    params: Vec<Vec<String>>,
    sourcefile: String,
}

impl FunctionDecl {
    pub fn new(
        ty: Vec<String>,
        name: String,
        params: Vec<Vec<String>>,
        sourcefile: String,
    ) -> Self {
        FunctionDecl {
            ty,
            name,
            params,
            sourcefile,
        }
    }

    pub fn proto(&self) -> String {
        return format!(
            "{} {}({})",
            self.ty.join(" "),
            self.name,
            self.params
                .iter()
                .map(|p| -> String { p.join(" ") })
                .into_iter()
                .collect::<Vec<String>>()
                .join(", ")
        );
    }

    pub fn harness(&self) -> String {
        let tmpl = CCAsset::get("template.cc").unwrap();
        let tmplfile = std::str::from_utf8(tmpl.data.as_ref()).unwrap();
        let hdr = self.sourcefile.clone();
        let fdplib = "fuzzed_data_provider.hh";
        let mut body = String::new();
        let mut input_params = Vec::new();
        for (i, params) in self.params.iter().enumerate() {
            let indir_level = params.iter().filter(|p| -> bool { p == &"*" }).count();
            if is_input(params.to_vec()) {
                let mut arraylen = "";
                if indir_level > 0 {
                    arraylen = "fdp.consume<size_t>()";
                }
                body += &format!(
                    "        {} param{} = fdp.consume<{}>({});\n",
                    params.join(" "),
                    i,
                    params.join(" "),
                    arraylen
                )
                .to_string();
                input_params.push(format!("param{}", i));
            } else {
                if indir_level > 0 {
                    let mut alloctype = params.clone();
                    alloctype.pop();
                    body += &format!(
                        "        {} param{} = new {};\n",
                        params.join(" "),
                        i,
                        alloctype.join(" ")
                    )
                    .to_string();
                    // TODO: & ?
                    input_params.push(format!("param{}", i));
                }
            }
        }
        body += &format!(
            "        {} rv = {}({});\n",
            self.ty.join(" "),
            self.name,
            input_params.join(", ")
        )
        .to_string();
        tmplfile
            .replace("{hdr}", &hdr)
            .replace("{fdplib}", fdplib)
            .replace("{body}", &body)
    }
}

/// Parser to extract function declarations from source code headers
struct FunctionDeclParser {
    /// The language object for the C language (from tree-sitter-c)
    language: Language,
    /// The tree-sitter parser object used to parse the source code
    parser: TParser,
}

impl FunctionDeclParser {
    /// Returns a new FunctionDeclParser with the given C language object
    ///
    /// # Arguments
    ///
    /// * `language` - The C language object as given by `tree_sitter_c()`
    pub fn new(language: Language) -> Self {
        let mut parser = TParser::new();
        parser.set_language(language).unwrap();

        Self { language, parser }
    }

    /// Find the top level `declaration` object starting from a `function_declaration`
    ///
    /// # Arguments
    ///
    /// * `nodes` - A vector used to recursively build the list of nodes. Initially contains
    ///           the node for the `function_declaration`
    ///
    /// # Returns
    ///
    /// * The built vector of nodes in order recursively upward in the AST from the
    ///   `function_declaration` to the `declaration`. For example:
    ///
    /// * function_declaration
    /// * pointer_declaration
    /// * declaration
    fn find_declaration<'a>(&self, nodes: &mut Vec<Node<'a>>) -> Vec<Node<'a>> {
        if nodes.last().unwrap().kind() == "declaration" {
            return nodes.to_vec();
        } else {
            match nodes.last().unwrap().parent() {
                Some(p) => {
                    nodes.push(p);
                    return self.find_declaration(nodes);
                }
                _ => {
                    return nodes.to_vec();
                }
            }
        }
    }

    pub fn parse(&mut self, text: String, sourcefile: String) -> Vec<FunctionDecl> {
        let mut rv = Vec::new();
        let tree = self.parser.parse(text.clone(), None).unwrap();
        let func_decl_query = Query::new(
            self.language,
            concat!("(function_declarator (identifier) @name (parameter_list) @params) @decl"),
        )
        .unwrap();
        let mut func_declarator_query_cursor = QueryCursor::new();

        /* Define a callback that extracts text from the raw string for matches */

        let matches = func_declarator_query_cursor.matches(
            &func_decl_query,
            tree.root_node(),
            text.as_bytes(),
        );

        for mtch in matches {
            /* The identifier */
            let mut declarator_identifier = mtch.nodes_for_capture_index(0);
            /* The parameter list match */
            let mut declarator_params = mtch.nodes_for_capture_index(1);
            /* The whole declarator match */
            let mut declarator_nodes = mtch.nodes_for_capture_index(2);

            if let (Some(identifier_node), Some(params_node), Some(declarator_node)) = (
                declarator_identifier.next(),
                declarator_params.next(),
                declarator_nodes.next(),
            ) {
                let mut declarator_nodes = Vec::new();
                declarator_nodes.push(declarator_node);

                let declaration_nodes = self.find_declaration(&mut declarator_nodes);

                let typedecl: Vec<String> = declaration_nodes
                    .iter()
                    .rev()
                    .take_while(|n| -> bool { n.kind() != "function_declarator" })
                    .map(|n| -> String {
                        String::from_utf8(
                            text.clone().as_bytes()
                                [n.children(&mut tree.walk()).next().unwrap().byte_range()]
                            .to_vec(),
                        )
                        .unwrap()
                    })
                    .collect();

                let identifier = String::from_utf8(
                    text.clone().as_bytes()[identifier_node.byte_range()].to_vec(),
                )
                .unwrap();

                let params_nodes: Vec<Vec<Node>> = params_node
                    .children(&mut tree.walk())
                    .filter(|n| -> bool {
                        n.kind() == "parameter_declaration" || n.kind() == "variadic_parameter"
                    })
                    .map(|n| -> Vec<Node> {
                        let mut node = n;
                        let mut param = Vec::new();
                        let mut stack: Vec<Node> = Vec::new();
                        stack.push(node);
                        while !stack.is_empty() {
                            node = stack.pop().unwrap();
                            if node.child_count() == 0 {
                                param.push(node);
                            } else {
                                for ch in node.children(&mut tree.walk()) {
                                    stack.push(ch);
                                }
                            }
                        }
                        param.reverse();
                        param
                    })
                    .collect();

                let params = params_nodes
                    .iter()
                    .map(|v| -> Vec<String> {
                        v.iter()
                            .map(|n| -> String {
                                String::from_utf8(text.clone().as_bytes()[n.byte_range()].to_vec())
                                    .unwrap()
                                    .trim()
                                    .to_string()
                            })
                            .collect()
                    })
                    .collect();

                rv.push(FunctionDecl::new(
                    typedecl,
                    identifier,
                    params,
                    sourcefile.clone(),
                ));
            }
        }
        rv
    }
}

fn extract_decls() -> Vec<FunctionDecl> {
    /* Parse the musl-libc source and obtain function prototypes  */
    extern "C" {
        fn tree_sitter_c() -> Language;
    }

    let c_language = unsafe { tree_sitter_c() };
    let mut parser = FunctionDeclParser::new(c_language);

    let musl_include_dir: PathBuf = PathBuf::from("musl/install/include");

    let mut decls: Vec<FunctionDecl> = Vec::new();

    for header in read_dir(musl_include_dir).unwrap() {
        if header.as_ref().unwrap().path().is_file() {
            /* Get the file contents as a string */
            let data = read_to_string(header.as_ref().unwrap().path())
                .expect("Unable to read header file");

            let name = header.as_ref().unwrap().file_name();
            debug!("Parsing {:?}", name);

            /* Filter out functions that aen't public or are unlikely to be exports (simple, by name)  */
            decls.extend(
                parser
                    .parse(data, name.to_string_lossy().to_string())
                    .into_iter()
                    .filter(|f| !f.name.starts_with("_") && !f.ty.join("").starts_with("static"))
                    .into_iter(),
            );
        }
    }
    for func in decls.iter() {
        debug!("{} {}({:?})", func.ty.join(" "), func.name, func.params)
    }

    decls
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
        let mut cc = ClangWrapper::new();

        if let Some(code) = cc
            .cpp(true)
            .silence(true)
            .from_args(&vec![
                format!("-B{}", cwd.to_string_lossy().to_string()),
                "-fuse-ld=musl-clang".to_string(),
                "-static-libgcc".to_string(),
                "-nostdinc".to_string(),
                "--sysroot".to_string(),
                format!("{}", libc.to_string_lossy().to_string()),
                "-isystem".to_string(),
                format!("{}", libc_inc.to_string_lossy().to_string()),
                "-L-user-start".to_string(),
                "-o".to_string(),
                format!("{}.bin", funcname),
                format!("-I{}", fdp_hdr_path.to_string_lossy().to_string()),
                format!("-L{}", libc_lib.to_string_lossy().to_string()),
                "-L-user-end".to_string(),
            ])
            .expect("Failed to parse command line for compiler.")
            .link_staticlib(&cwd, "libc-fuzzer")
            .add_arg("-fsanitize-coverage=trace-pc-guard")
            .run()
            .expect("Failed to run compiler wrapper")
        {
            std::process::exit(code);
        }
    }

    Ok(())
}
