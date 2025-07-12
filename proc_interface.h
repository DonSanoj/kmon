#ifndef PROC_INTERFACE_H
#define PROC_INTERFACE_H

#include "kmon.h"

// Function declarations
int kmon_proc_show(struct seq_file *m, void *v);
int kmon_proc_open(struct inode *inode, struct file *file);
ssize_t kmon_proc_write(struct file *file, const char __user *buffer,
                       size_t count, loff_t *pos);
int create_proc_interface(void);
void cleanup_proc_interface(void);

// Proc operations structure
extern const struct proc_ops kmon_proc_ops;

#endif /* PROC_INTERFACE_H */