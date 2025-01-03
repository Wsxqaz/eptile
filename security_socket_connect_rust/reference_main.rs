#![allow(unreachable_pub)]
#![allow(warnings)]

use core::ffi::c_uint;
use core::arch::asm;
use kernel::prelude::*;
mod bindings_generated;
mod bindings_helpers_generated;
use bindings_generated::*;
use bindings_helpers_generated::*;

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
    fn filp_open(path: *const i8, flags: i32, mode: i32) -> *mut file;
    fn filp_close(f: *mut file, f2: *mut file);
    fn mutex_lock(m: &mut mutex);
    fn mutex_unlock(m: &mut mutex);
    fn __kmalloc(size: usize, flags: i32) -> *mut u8;
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

fn strtoul(s: *const i8) -> u64 {
    unsafe {
        let mut i = 0;
        let mut n: u64 = 0;
        while *s.wrapping_offset(i) != 0 {
            let mut c = *s.wrapping_offset(i);

            let mut d = -1;

            if c >= 'a' as i8 && c <= 'f' as i8 {
                d = (c as i32).wrapping_sub('a' as i32).wrapping_add(10);
            }

            if c >= 'A' as i8 && c <= 'F' as i8 {
                d = (c as i32).wrapping_sub('A' as i32).wrapping_add(10);
            }

            if c >= '0' as i8 && c <= '9' as i8 {
                d = (c as i32).wrapping_sub('0' as i32);
            }

            if d == -1 {
                _printk("Invalid number\n\0".as_ptr() as *const i8);
                _printk("c: %c\n\0".as_ptr() as *const i8, c as u8 as c_uint);
                _printk("d: %d\n\0".as_ptr() as *const i8, d);
                break;
            }
            n = n.wrapping_mul(16).wrapping_add(d as u64);
            i = i.wrapping_add(1);
        }
        n
    }
}

fn strcmp(s1: *const i8, s2: *const i8) -> i32 {
    unsafe {
        let mut i = 0;
        while *s1.wrapping_offset(i) != 0 && *s2.wrapping_offset(i) != 0 {
            if *s1.wrapping_offset(i) != *s2.wrapping_offset(i) {
                return (*s1.wrapping_offset(i) as i32).wrapping_sub(*s2.wrapping_offset(i) as i32);
            }
            i = i.wrapping_add(1);
        }
        return (*s1.wrapping_offset(i) as i32).wrapping_add(*s2.wrapping_offset(i) as i32);
    }
}

fn x86_put_jmp(a: *mut u8, f: *mut u8, t: *mut u8) {
    unsafe {
        let offset = t.wrapping_sub(f as usize) as i64;
        let offset = offset.wrapping_sub(5);
        *a = 0xe9;
        *(a.wrapping_offset(1)) = (offset & 0xff) as u8;
        *(a.wrapping_offset(2)) = ((offset >> 8) & 0xff) as u8;
        *(a.wrapping_offset(3)) = ((offset >> 16) & 0xff) as u8;
        *(a.wrapping_offset(4)) = ((offset >> 24) & 0xff) as u8;
    }
}

static mut buff: [u8; 4096] = [0; 4096];

fn _read_file(file: *mut file) -> u32 {
    unsafe {
        let mut m: *mut seq_file = (*file).private_data as *mut seq_file;
        _printk("m: %px\n\0".as_ptr() as *const i8, m as usize);
        mutex_lock(&mut (*m).lock);
        _printk("mutex locked\n\0".as_ptr() as *const i8);

        if (*m).buf == 0 as *mut i8 {
            (*m).buf = buff.as_mut_ptr() as *mut i8;
                // __kmalloc(4096, 0) as *mut i8;

            (*m).size = 4096;
        }

        _printk("m->buf: %llx\n\0".as_ptr() as *const i8, (*m).buf as usize);

        let start = match (*(*m).op).start {
            Some(f) => f,
            None => return 0,
        };
        let mut p = start(m, &mut (*m).index);


        (*m).count = 0;

        let show = match (*(*m).op).show {
            Some(f) => f,
            None => return 0,
        };
        let err = show(m, p);
        let next = match (*(*m).op).next {
            Some(f) => f,
            None => return 0,
        };
        p = next(m, p, &mut (*m).index);

        mutex_unlock(&mut (*m).lock);

        return (*m).count as u32;
    }
}

fn read_kallsym(name: *const i8) -> usize {
    unsafe {
        let mut f: *mut file = filp_open("/proc/kallsyms\0".as_ptr() as *const i8, 0, 0);
        _printk("f: %llx\n\0".as_ptr() as *const i8, f as usize);
        if f.is_null() {
            _printk("Failed to open /proc/kallsyms\n\0".as_ptr() as *const i8);
            return 0;
        }

        let m: *mut seq_file = (*f).private_data as *mut seq_file;
        let mut read: u32 = _read_file(f);
        _printk("read: %u\n\0".as_ptr() as *const i8, read);
        _printk("buf: %s\n\0".as_ptr() as *const i8, (*m).buf);

        loop {
            if read == 0 {
                break;
            }


            let mut i = 0;
            loop {
                if *((*m).buf.wrapping_offset(i)) == '\n' as i8 {
                    break;
                }

                if *( (*m).buf.wrapping_offset(i) ) == '\0' as i8 {
                    break;
                }

                if *((*m).buf.wrapping_offset(i)) == '\t' as i8 {
                    break;
                }

                i = i.wrapping_add(1);
            }
            let t = (*m).buf.wrapping_offset(i);
            (*t) = '\0' as i8;

            if strcmp((*m).buf.wrapping_add(19), name) == 0 {
                _printk("Found %s\n\0".as_ptr() as *const i8, name);
                _printk("Line: %s\n\0".as_ptr() as *const i8, (*m).buf);
                let addr = strtoul((*m).buf);
                _printk("Address: %llx\n\0".as_ptr() as *const i8, addr);
                filp_close(f, 0 as *mut file);
                return addr as usize;
            }

            read = _read_file(f);
        }
        filp_close(f, 0 as *mut file);
        return 0;
    }
}

// fn inet_ntoa(addr: *mut in_addr, buf: *mut i8) -> *mut i8 {
//     unsafe {
//         let addr = (*addr).s_addr;
//         let a = (addr >> 0) & 0xff;
//         let b = (addr >> 8) & 0xff;
//         let c = (addr >> 16) & 0xff;
//         let d = (addr >> 24) & 0xff;
//         let len = snprintf(buf, 16, "%d.%d.%d.%d".as_ptr() as *const i8, a, b, c, d);
//         buf
//     }
// }


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

        let addr = read_kallsym("security_socket_connect\0".as_ptr() as *const i8);
        unsafe {
            _printk("security_socket_connect: %llx\n\0".as_ptr() as *const i8, addr);
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
