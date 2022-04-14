use std::fs::{read_dir, read_to_string};
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, TreeCursor};

fn ts_text_callback<'a>(source: &'a str) -> impl Fn(Node) -> &'a [u8] {
    move |n| &source.as_bytes()[n.byte_range()]
}
fn main() {
    /* Parse the musl-libc source and obtain function prototypes  */
    extern "C" {
        fn tree_sitter_c() -> Language;
    }

    let c_language = unsafe { tree_sitter_c() };

    let mut parser = Parser::new();
    parser.set_language(c_language).unwrap();

    let musl_include_dir: PathBuf = PathBuf::from("musl/install/include");

    for header in read_dir(musl_include_dir).unwrap() {
        if header.as_ref().unwrap().path().is_file() {
            /* Get the file contents as a string */
            let data = read_to_string(header.as_ref().unwrap().path())
                .expect("Unable to read header file");

            /* Grab the parse tree from tree-sitter */
            let tree = parser.parse(data.clone(), None).unwrap();
            // println!("Parsed {:?}", header.as_ref().unwrap().file_name());
            // println!("{}", tree.root_node().to_sexp());

            /* Query the parse tree for function declarations  */
            let func_decl_querystr = "(function_declarator declarator: \
                    (identifier) parameters: (parameter_list))";
            let func_decl_query = Query::new(c_language, func_decl_querystr).unwrap();
            let mut func_decl_query_cursor = QueryCursor::new();

            /* Define a callback that extracts text from the raw string for matches */

            let all_matches =
                func_decl_query_cursor.matches(&func_decl_query, tree.root_node(), data.as_bytes());

            let nodes: Vec<&Node> = all_matches
                .flat_map(|query_match| {
                    query_match
                        .captures
                        .iter()
                        .map(|query_capture| &query_capture.node)
                })
                .collect();

            for node in nodes {}
        }
    }
}
