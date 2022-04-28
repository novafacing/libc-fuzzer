use std::fs::{read_dir, read_to_string};
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

struct FunctionDecl {
    ty: String,
    name: String,
    params: Vec<String>,
}

impl FunctionDecl {
    pub fn new(ty: String, name: String, params: Vec<String>) -> Self {
        FunctionDecl { ty, name, params }
    }
}

struct FunctionDeclParser {
    language: Language,
    parser: Parser,
}

impl FunctionDeclParser {
    pub fn new(language: Language) -> Self {
        let mut parser = Parser::new();
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

                let typedecl_start = declaration_nodes.last().unwrap().start_byte();
                let typedecl_end = declaration_nodes
                    .first()
                    .unwrap()
                    .child_by_field_name("declarator")
                    .unwrap()
                    .start_byte();

                let typedecl = String::from_utf8(
                    text.clone().as_bytes()[typedecl_start..typedecl_end].to_vec(),
                )
                .unwrap();

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

fn main() {
    /* Parse the musl-libc source and obtain function prototypes  */
    extern "C" {
        fn tree_sitter_c() -> Language;
    }

    let c_language = unsafe { tree_sitter_c() };
    let mut parser = FunctionDeclParser::new(c_language);

    let musl_include_dir: PathBuf = PathBuf::from("musl/install/include");

    for header in read_dir(musl_include_dir).unwrap() {
        if header.as_ref().unwrap().path().is_file() {
            /* Get the file contents as a string */
            let data = read_to_string(header.as_ref().unwrap().path())
                .expect("Unable to read header file");

            let name = header.as_ref().unwrap().file_name();
            println!("Parsing {:?}", name);

            /* Grab the parse tree from tree-sitter */

            let funcs = parser.parse(data);
            for func in funcs {
                if !func.name.starts_with("_") && !func.ty.starts_with("static") {
                    println!("{} {}({:?})", func.ty, func.name, func.params)
                }
            }
        }
    }
}
