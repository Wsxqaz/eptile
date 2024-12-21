#include <asm/insn.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/trace_events.h>
#include <linux/uaccess.h>


long line_to_addr(char *line);
long find_kallsym(char *name);

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

long line_to_addr(char *line) {
    return simple_strtoul(line, NULL, 16);
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


static int driver_entry(void)
{
  printk(KERN_INFO "Gello, world!\n");
  void *addr = (void *)find_kallsym("trace_call_bpf");
  pr_info("addr: %px\n", addr);
  // read_kallsyms();
  return 0;
}

static void driver_exit(void)
{
  printk(KERN_INFO "Goodbye, world!\n");
}

MODULE_LICENSE("GPL");
module_init(driver_entry);
module_exit(driver_exit);
