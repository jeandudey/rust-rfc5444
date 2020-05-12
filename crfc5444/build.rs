extern crate cbindgen;

use std::env;
use std::path::PathBuf;

use cbindgen::Config;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut config_file = PathBuf::from(crate_dir.clone());
    config_file.push("cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(
            Config::from_file(config_file)
                .expect("Unable to parse cbindgen configuration"),
        )
        .generate()
        .expect("Unable to generate RFC 5444 bindings")
        .write_to_file("rfc5444.h");
}
