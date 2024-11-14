#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stop_machine.h>
#include <asm/insn.h>
#include <linux/trace_events.h>


extern void *KHOOK_STUB_hook_noref_end;
extern void *KHOOK_STUB_hook_noref;


long line_to_addr(char *line);
long find_kallsym(char *name);
int lde_get_length(const void *p);
unsigned int original_trace_call_bpf(struct trace_event_call *call, void *ctx);
unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx);
long run_hook(void * addr, int len);
long write_kernel(void * addr, int len);
int _run(void *data);
int reset(void *data);

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

long find_kallsym(char *name) {
  char * kallsyms_path = "/home/wsxqaz/kallsyms\0";
  struct file *file = filp_open(kallsyms_path, O_RDONLY, 0);

  printk(KERN_INFO "file: %p\n", file);
  printk(KERN_INFO "file->f_op: %p\n", file->f_op);
  printk(KERN_INFO "file->f_op->read: %p\n", file->f_op->read);
  printk(KERN_INFO "file->f_op->read_iter: %p\n", file->f_op->read_iter);

  char * buf = kmalloc(4096, GFP_KERNEL);
  long long pos = 0;

  int read = kernel_read(file, buf, 4096, &pos);
  while (read > 0) {
    for (int i = 0; i < 4096; i++) {
        if (buf[i] == '\n') {
          int j = i + 1;
          while (buf[j] != '\n') {
            j++;
          }
          char tmp = buf[j];
          buf[j] = '\0';
          if (i + 20 >= 4096) {
            buf[j] = tmp;
            continue;
          }
          // printk(KERN_INFO "line: %s\n", buf + i + 20);
          if (strcmp(buf + i + 20, name) != 0) {
            buf[j] = tmp;
            continue;
          }
          buf[j] = tmp;
          long addr = line_to_addr(buf + i + 1);
          filp_close(file, NULL);
          kfree(buf);
          return addr;
        }
    }
    read = kernel_read(file, buf, 4096, &pos);
  }
  filp_close(file, NULL);
  kfree(buf);
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

unsigned int original_trace_call_bpf(struct trace_event_call *call, void *ctx) {
  asm(".rept 0x80\n.byte 0\n.endr\n");
  return 0;
}

unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx) {
  printk(KERN_INFO "hook_trace_call_bpf\n");
  printk(KERN_INFO "call: %px\n", call);
  printk(KERN_INFO "ctx: %px\n", ctx);
  printk(KERN_INFO "call->class->system: %s\n", call->class->system);
  return original_trace_call_bpf(call, ctx);
}

long write_kernel(void * addr, int len) {
	long res = 0, cr0, cr4;

	asm volatile ("cli\n");

	cr0 = x86_read_cr0();
	cr4 = x86_read_cr4();

	if (cr4 & X86_CR4_CET)
		x86_write_cr4(cr4 & ~X86_CR4_CET);
	x86_write_cr0(cr0 & ~X86_CR0_WP);

	res = run_hook(addr, len);

	x86_write_cr0(cr0);
	if (cr4 & X86_CR4_CET)
		x86_write_cr4(cr4);

	asm volatile ("sti\n");

	return res;
}

int ORIG_LEN = 0;

long run_hook(void * addr, int len ) {
  ORIG_LEN = len;
  for (int i = 0; i < len; i++) {
    printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)addr)[i]);
    *((unsigned char *)original_trace_call_bpf + i) = ((unsigned char *)addr)[i];
  }

  // for (int i = 0; i < len + 6; i++) {
  //   printk(KERN_INFO "pre [%d]: 0x%02x ", i, ((unsigned char *)original_trace_call_bpf)[i]);
  // }
  // x86_put_jmp(original_trace_call_bpf + len, original_trace_call_bpf + len, addr + len);
  // for (int i = 0; i < len + 6; i++) {
  //   printk(KERN_INFO "post [%d]: 0x%02x ", i, ((unsigned char *)original_trace_call_bpf)[i]);
  // }
  x86_put_jmp(addr, addr, hook_trace_call_bpf);

  return 0;
}

struct args {
  void *addr;
  int len;
};

int _run(void *data) {
  struct args *args = (struct args *)data;
  write_kernel(
    args->addr,
    args->len
  );

  return 0;
}


static int driver_entry(void)
{
  void * addr = (void *)find_kallsym("trace_call_bpf");
  printk(KERN_INFO "trace_call_bpf: %px\n", addr);

  if (addr == 0) {
    printk(KERN_INFO "trace_call_bpf not found\n");
    return 0;
  }

  int len = lde_get_length((void *)addr);
  printk(KERN_INFO "trace_call_bpf len: %d\n", len);
  while (len < 5) {
    printk(KERN_INFO "trace_call_bpf len: %d\n", len);
    len += lde_get_length((void *)(addr + len));
  }
  printk(KERN_INFO "trace_call_bpf len: %d\n", len);
  struct args args = {
    .addr = addr,
    .len = len
  };
  stop_machine(_run, &args, NULL);

  return 0;
}

int reset(void *data) {
  printk(KERN_INFO "trace_call_bpf: %px\n", data);
  for (int i = 0; i < ORIG_LEN; i++) {
    printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)data)[i]);
    ((unsigned char *)data)[i] = ((unsigned char *)original_trace_call_bpf)[i];
  }
  return 0;
}

static void driver_exit(void)
{
  void * addr = (void *)find_kallsym("trace_call_bpf");
  stop_machine(reset, addr, NULL);
  printk(KERN_INFO "Goodbye, world!\n");
}

MODULE_LICENSE("GPL");
module_init(driver_entry);
module_exit(driver_exit);
