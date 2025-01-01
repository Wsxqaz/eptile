use core::arch::asm;
use kernel::prelude::*;

module! {
    type: ReferenceMain,
    name: "reference_main",
    author: "author",
    description: "Description",
    license: "GPL",
}

struct ReferenceMain {
    orig: [u8; 16],
    orig_len: usize,
}

#[no_mangle]
extern "C" {
    fn _printk(s: *const i8, ...) -> i32;
}


fn x86_read_cr0() -> u64 {
    let cr0: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0);
    }
    cr0
}

fn x86_write_cr0(cr0: u64) {
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0);
    }
}

fn x86_read_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4);
    }
    cr4
}

fn x86_write_cr4(cr4: u64) {
    unsafe {
        asm!("mov cr4, {}", in(reg) cr4);
    }
}

impl kernel::Module for ReferenceMain {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {
            _printk("Hello from reference_main\n\0".as_ptr() as *const i8);
        }
        let cr0 = x86_read_cr0();
        unsafe {
            _printk("CR0: %llx\n\0".as_ptr() as *const i8, cr0);
        }
        let cr4 = x86_read_cr4();
        unsafe {
            _printk("CR4: %llx\n\0".as_ptr() as *const i8, cr4);
        }

        Ok(Self {
            orig: [0; 16],
            orig_len: 0,
        })
    }
}

impl Drop for ReferenceMain {
    fn drop(&mut self) {
        unsafe {
            _printk("Goodbye from reference_main\n\0".as_ptr() as *const i8);
        }
    }
}
