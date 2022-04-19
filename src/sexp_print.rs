/* Pretty-printer for s-expressions */

use sexp::Sexp;

const SINGLE_LINE_LIMIT: usize = 4;

pub fn sexp_print(exp: &Sexp, indent: usize) {
    match exp {
        Sexp::Atom(a) => {
            println!("{}{}", " ".repeat(indent), a);
        }
        Sexp::List(l) => {
            println!("{}(", " ".repeat(indent));
            for e in l.iter() {
                sexp_print(e, indent + 2);
            }
            println!("{})", " ".repeat(indent));
        }
    }
}
