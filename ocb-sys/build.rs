#![deny(warnings)]
#![allow(unstable)]

extern crate gcc;
extern crate libc;

use std::default::Default;
use std::borrow::ToOwned;
use std::io::{File, Command};
use std::os;
use std::str;
use libc::c_int;

fn main() {
    let out_dir = os::getenv("OUT_DIR").unwrap();

    gcc::compile_library("libocb.a", &gcc::Config {
        flags: vec!["-O3".to_owned(), "-fPIC".to_owned()],
        ..Default::default()
    }, &["ocb.c"]);

    let out = format!("{}/print_ae_ctx_sizeof", out_dir);

    // Won't work when cross-compiling. But even if it somehow
    // runs and gives the wrong answer, there's a run-time check
    // as well.
    Command::new("gcc")
        .args(&["-Wall", "-Werror", "-lcrypto"])
        .arg("-o").arg(&out[])
        .arg("print_ae_ctx_sizeof.c")
        .arg(format!("{}/libocb.a", out_dir))
        .status().unwrap();

    let output = Command::new(&out[]).output().unwrap();
    assert!(output.status.success());

    let size: c_int = str::from_utf8(&output.output[]).unwrap()
        .trim_right().parse().unwrap();

    // sanity check
    assert!(size > 0);
    assert!(size < 8192);

    let dest = Path::new(out_dir);
    let mut f = File::create(&dest.join("generated.rs")).unwrap();
    f.write_str(&format!("pub const AE_CTX_SIZEOF: usize = {};\n", size)[])
        .unwrap();
}
