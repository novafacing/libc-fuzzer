use clap::Parser;
use log::{debug, error, info, warn};
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

#[derive(Clone)]
struct FunctionDecl {
    ty: Vec<String>,
    name: String,
    params: Vec<String>,
}

impl FunctionDecl {
    pub fn new(ty: Vec<String>, name: String, params: Vec<String>) -> Self {
        FunctionDecl { ty, name, params }
    }

    pub fn proto(&self) -> String {
        return format!(
            "{} {}({})",
            self.ty.join(""),
            self.name,
            self.params.join(", ")
        );
    }
}

struct FunctionDeclParser {
    language: Language,
    parser: TParser,
}

impl FunctionDeclParser {
    pub fn new(language: Language) -> Self {
        let mut parser = TParser::new();
        parser.set_language(language).unwrap();

        Self { language, parser }
    }

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

    pub fn parse(&mut self, text: String) -> Vec<FunctionDecl> {
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

                for node in declaration_nodes.iter().rev() {
                    println!("kind: {}", node.kind());
                }
                println!("");

                let mut typedecl: Vec<String> = declaration_nodes
                    .iter()
                    .rev()
                    .take_while(|n| -> bool { n.kind() != "function_declarator" })
                    .map(|n| -> String {
                        String::from_utf8(text.clone().as_bytes()[n.byte_range()].to_vec()).unwrap()
                    })
                    .collect();

                typedecl.pop();

                let identifier = String::from_utf8(
                    text.clone().as_bytes()[identifier_node.byte_range()].to_vec(),
                )
                .unwrap();

                let params: Vec<String> = params_node
                    .children(&mut tree.walk())
                    .filter(|n| -> bool {
                        n.kind() == "parameter_declaration" || n.kind() == "variadic_parameter"
                    })
                    .map(|n| -> String {
                        String::from_utf8(text.clone().as_bytes()[n.byte_range()].to_vec()).unwrap()
                    })
                    .collect();

                rv.push(FunctionDecl::new(typedecl, identifier, params))
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
                    .parse(data)
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

    for (funcname, proto) in to_fuzz
        .iter()
        .map(|f| -> (String, String) { (f.name.clone(), f.proto()) })
    {
        info!("Generating fuzzer for {}: {}", funcname, proto);
    }

    Ok(())
}
