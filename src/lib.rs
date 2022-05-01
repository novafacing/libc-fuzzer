use log::debug;
use rust_embed::RustEmbed;
use std::fs::{read_dir, read_to_string};
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser as TParser, Query, QueryCursor};

#[derive(RustEmbed)]
#[folder = "fuzzed_data_provider"]
struct CCAsset;

/// FunctionDecl - Function Declaration Information
#[derive(Clone)]
pub struct FunctionDecl {
    /// A list of tokens found in the return type of the function
    pub ty: Vec<String>,
    /// The name of the function
    pub name: String,
    /// A list of lists of the tokens found in each parameter to the function
    pub params: Vec<Vec<String>>,
    /// The source file the declaration was extracted from
    pub sourcefile: String,
}

impl FunctionDecl {
    /// Create a new FunctionDecl from its components
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

    /// Check if a parameter is "probably" an input parameter
    /// to distinguish between a pointer passed in that is filled in by the function
    /// and a pointer passed in that is used by the function as input. Generally for
    /// libc, `const` indicates an input, but that may not be true for other libraries
    ///
    /// # Arguments
    ///
    /// * `params` The parameter to check
    ///
    /// # Returns
    ///
    /// * Whether the parameter is probably used as input to the function and should
    ///   contain fuzzer data
    fn is_input(&self, param: Vec<String>) -> bool {
        if param.contains(&"*".to_string()) {
            return param.contains(&"const".to_string());
        } else {
            return true;
        }
    }

    /// Construct a human readable string of the function prototype
    ///
    /// # Returns
    ///
    /// * A human readable string of the function prototype
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

    /// Generate the harness CC code to wrap the desired library function
    ///
    /// # Arguments
    ///
    /// * `tmplfile` The name of the template file to drop the harness body into. This should
    ///   either be `template.cc` or `template_manual.cc`
    pub fn harness(&self, tmplfile: String) -> String {
        let tmpl = CCAsset::get(&tmplfile).unwrap();
        let tmplfile = std::str::from_utf8(tmpl.data.as_ref()).unwrap();
        let hdr = self.sourcefile.clone();
        let fdplib = "fuzzed_data_provider.hh";
        let mut body = String::new();
        let mut input_params = Vec::new();
        for (i, params) in self.params.iter().enumerate() {
            /* Kind of dumb, but this does work to check the level of indirection generally */
            let indir_level = params.iter().filter(|p| -> bool { p == &"*" }).count();

            /* The alloctype is the type that will be passed into fdp.consume<ALLOCTYPE>() */
            let mut alloctype = params.clone();

            /* Remove a level of indirection if there is one */
            if indir_level > 0 {
                alloctype.pop();
            }

            /* Remove a const from the type to pass to template parameter if there is one */
            if alloctype.first().unwrap() == "const" {
                alloctype.remove(alloctype.iter().position(|p| *p == "const").unwrap());
            }

            /* If the type is an input, we fuzz its contents */
            if self.is_input(params.to_vec()) {
                let mut arraylen = "";
                if indir_level > 0 {
                    arraylen = "fdp.consume<uint8_t>()";
                }
                body += &format!(
                    "            {} param{} = fdp.consume<{}>({});\n",
                    params.join(" "),
                    i,
                    alloctype.join(" "),
                    arraylen
                )
                .to_string();
                input_params.push(format!("param{}", i));
            /* If the type isn't an input, we just allocate space and assume it is an output */
            } else {
                body += &format!(
                    "            {} param{} = new {}[1];\n",
                    params.join(" "),
                    i,
                    alloctype.join(" ")
                )
                .to_string();
                // TODO: & ?
                input_params.push(format!("param{}", i));
            }
        }

        /* Insert the call to the function */
        body += &format!(
            "            {} rv = {}({});\n",
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
pub struct FunctionDeclParser {
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

    /// Parse the source file and construct a vector of function declarations that are in the file
    /// this isn't terribly reliable and makes some assumptions about the code (for example, that
    /// the declarations aren't totally opaque like in glibc) but finds every libc export that I
    /// expected to see plus/minus a few out of musl...#todo: improve!
    ///
    /// # Arguments
    ///
    /// * `text` The raw contents of `sourcefile`
    /// * `sourcefile` The header source file name
    ///
    /// # Returns
    ///
    /// * A vector of the function declarations found in the file
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

/// Top level function to parse through the musl libc source and extract the function
/// declarations from it
pub fn extract_decls() -> Vec<FunctionDecl> {
    /* Parse the musl-libc source and obtain function prototypes  */
    #[link(name = "tree-sitter")]
    extern "C" {
        #[link_name = "tree_sitter_c"]
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
