#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stop_machine.h>
#include <asm/insn.h>
#include <linux/trace_events.h>
#include <linux/rcupdate.h>
#include <linux/bpf.h>
#include <linux/filter.h>


extern void __this_cpu_preempt_check(const char *op);
extern void __rcu_read_lock(void);
extern int rcu_read_lock_held(void);

void notrace bpf_prog_inc_misses_counter(struct bpf_prog *prog)
{
	struct bpf_prog_stats *stats;
	unsigned int flags;

	stats = this_cpu_ptr(prog->stats);
	flags = u64_stats_update_begin_irqsave(&stats->syncp);
	u64_stats_inc(&stats->misses);
	u64_stats_update_end_irqrestore(&stats->syncp, flags);
}


long line_to_addr(char *line);
long find_kallsym(char *name);
int lde_get_length(const void *p);
void original_trace_call_bpf(struct trace_event_call *call, void *ctx);
unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx);
long run_hook(void * addr, int len);
long write_kernel(void * addr, int len, long (*fn)(void *, int));
int _run(void *data);
long hook_reset(void *data, int len);
int _hook_reset(void *data);

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
      pr_info("m->buf: %s\n", m->buf);
      pr_info("name: %s\n", name);
      pr_info("m->buf + 19: %s\n", m->buf + 19);
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

void original_trace_call_bpf(struct trace_event_call *call, void *ctx) {
  asm(".rept 0x80\n.byte 0\n.endr\n");
}


unsigned int hook_trace_call_bpf(struct trace_event_call *call, void *ctx) {
  printk(KERN_INFO "hook_trace_call_bpf\n");
  printk(KERN_INFO "call: %px\n", call);
  printk(KERN_INFO "ctx: %px\n", ctx);
  printk(KERN_INFO "call->class->system: %s\n", call->class->system);


  int ret = __this_cpu_inc_return(*_bpf_prog_active);

  if (ret != 1) {
    rcu_read_lock();
    bpf_prog_inc_misses_counters(rcu_dereference(call->prog_array));
    rcu_read_unlock();
    ret = 0;
    goto out;
  }

  rcu_read_lock();
  ret = bpf_prog_run_array(rcu_dereference(call->prog_array), ctx, bpf_prog_run);
  rcu_read_unlock();

out:
  __this_cpu_dec(*_bpf_prog_active);

  return ret;
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

int ORIG_LEN = 0;

long run_hook(void * addr, int len ) {
  ORIG_LEN = len;

  for (int i = 0; i < len; i++) {
    printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)addr)[i]);
  }
  for (int i = 0; i < len + 6; i++) {
    printk(KERN_INFO "pre orig [%d]: 0x%02x ", i, ((unsigned char *)original_trace_call_bpf)[i]);
  }

  memcpy(original_trace_call_bpf, addr, len);
  x86_put_jmp(original_trace_call_bpf + len, original_trace_call_bpf + len, addr + len);

  for (int i = 0; i < len + 6; i++) {
    printk(KERN_INFO "post [%d]: 0x%02x ", i, ((unsigned char *)original_trace_call_bpf)[i]);
  }
  x86_put_jmp(addr, addr, hook_trace_call_bpf);

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


static int driver_entry(void)
{
  void * addr = (void *)find_kallsym("trace_call_bpf");
  _bpf_prog_active = (int *)find_kallsym("bpf_prog_active");
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
  stop_machine(__run, &args, NULL);

  return 0;
}

int _hook_reset(void *data) {
  struct args *args = (struct args *)data;

  return write_kernel(args->addr, args->len, hook_reset);
}

long hook_reset(void *data, int len) {
  printk(KERN_INFO "trace_call_bpf: %px\n", data);

  for (int i = 0; i < len; i++) {
    printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)data)[i]);
  }
  // memcpy(data, original_trace_call_bpf, len);
  for (int i = 0; i < len; i++) {
    ((unsigned char *)data)[i] = ((unsigned char *)original_trace_call_bpf)[i];
  }
  for (int i = 0; i < len; i++) {
    printk(KERN_INFO "addr [%d]: 0x%02x ", i, ((unsigned char *)data)[i]);
  }
  return 0;
}

static void driver_exit(void)
{
  void * addr = (void *)find_kallsym("trace_call_bpf");
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
