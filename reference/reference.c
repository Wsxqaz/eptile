#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stop_machine.h>
#include <asm/insn.h>

MODULE_LICENSE("GPL");

long line_to_addr(char *line);
long find_kallsym(char *name);
int lde_get_length(const void *p);
unsigned int original_trace_call_bpf(struct trace_event_call *call, void *ctx);
unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx);
int run_hook(void *data);

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
  asm(".rept 0x10\n.byte 0\n.endr\n");
  return 0;
}

unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx) {
  printk(KERN_INFO "hook_trace_call_bpf\n");
  return original_trace_call_bpf(call, ctx);
}

int run_hook(void *data) {
  long addr = find_kallsym("trace_call_bpf");
  printk(KERN_INFO "trace_call_bpf: %lx\n", addr);

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

  memcpy(addr, original_trace_call_bpf, len);
  x86_put_jmp(original_trace_call_bpf + len, original_trace_call_bpf + len, addr + len);
  x86_put_jmp(addr, addr, hook_trace_call_bpf);

  return 0;
}

static int driver_entry(void)
{
  run_hook(NULL);

  return 0;
}

static void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
