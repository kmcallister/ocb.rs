#![feature(libc)]
#![deny(warnings)]

extern crate gcc;
extern crate libc;

use std::{fs, env, str};
use std::io::Write;
use std::process::Command;
use std::path::Path;
use libc::c_int;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    gcc::Config::new()
        .file("ocb.c")
        .flag("-O3").flag("-fPIC")
        .compile("libocb.a");

    let out = format!("{}/print_ae_ctx_sizeof", out_dir);

    // Won't work when cross-compiling. But even if it somehow
    // runs and gives the wrong answer, there's a run-time check
    // as well.
    Command::new("gcc")
        .args(&["-Wall", "-Werror"])
        .arg("-o").arg(&out)
        .arg("print_ae_ctx_sizeof.c")
        .arg(format!("{}/libocb.a", out_dir))
        .arg("-lcrypto")
        .status().unwrap();

    let output = Command::new(&out).output().unwrap();
    assert!(output.status.success());

    let size: c_int = str::from_utf8(&output.stdout).unwrap()
        .trim_right().parse().unwrap();

    // sanity check
    assert!(size > 0);
    assert!(size < 8192);

    let dest = Path::new(&out_dir);
    let mut f = fs::File::create(&dest.join("generated.rs")).unwrap();
    write!(&mut f, "pub const AE_CTX_SIZEOF: usize = {};\n", size)
        .unwrap();
}
