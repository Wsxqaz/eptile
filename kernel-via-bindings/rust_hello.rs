// SPDX-License-Identifier: GPL-2.0

//! Rust hello.

use kernel::prelude::*;

module! {
    type: RustHello,
    name: "rust_hello",
    author: "Rust for Linux Contributors",
    description: "Rust minimal sample",
    license: "GPL",
}

struct RustHello {}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("[rust_hello] Hello world!\n");
        pr_info!("[rust_hello] Hello world!\n");
        pr_info!("[rust_hello] Hello world!\n");
        Ok(RustHello {})
    }
}

impl Drop for RustHello {
    fn drop(&mut self) {
        pr_info!("Hello exit!\n");
    }
}
