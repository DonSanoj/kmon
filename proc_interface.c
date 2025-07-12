#include "proc_interface.h"

// Proc file operations for reading hash history
int kmon_proc_show(struct seq_file *m, void *v)
{
    int i, j, start_idx;
    struct hash_entry *entry;
    
    seq_printf(m, "Kernel Integrity Monitor - Hash History\n");
    seq_printf(m, "Monitoring: %s\n", monitoring_enabled ? "Enabled" : "Disabled");
    seq_printf(m, "Total entries: %d\n", hash_count);
    seq_printf(m, "Check interval: %d seconds\n\n", MONITOR_INTERVAL_SEC);
    
    // Show entries in chronological order
    start_idx = (hash_count == MAX_HASH_HISTORY) ? current_index : 0;
    
    for (i = 0; i < hash_count; i++) {
        int idx = (start_idx + i) % MAX_HASH_HISTORY;
        entry = &hash_history[idx];
        
        seq_printf(m, "[%d] %s%s%lld.%09ld: ",
                   i + 1,
                   entry->is_baseline ? "BASELINE " : "",
                   entry->is_anomaly ? "ANOMALY " : "",
                   (long long)entry->timestamp.tv_sec,
                   entry->timestamp.tv_nsec);
        
        for (j = 0; j < HASH_LENGTH; j++)
            seq_printf(m, "%02x", entry->hash[j]);
        seq_printf(m, "\n");
    }
    
    return 0;
}

int kmon_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, kmon_proc_show, NULL);
}

ssize_t kmon_proc_write(struct file *file, const char __user *buffer,
                       size_t count, loff_t *pos)
{
    char cmd[16];
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (strncmp(cmd, "stop", 4) == 0) {
        monitoring_enabled = false;
        pr_info("kmon: Monitoring disabled\n");
    } else if (strncmp(cmd, "start", 5) == 0) {
        monitoring_enabled = true;
        pr_info("kmon: Monitoring enabled\n");
    } else if (strncmp(cmd, "clear", 5) == 0) {
        hash_count = 0;
        current_index = 0;
        pr_info("kmon: Hash history cleared\n");
    }
    
    return count;
}

const struct proc_ops kmon_proc_ops = {
    .proc_open = kmon_proc_open,
    .proc_read = seq_read,
    .proc_write = kmon_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int create_proc_interface(void)
{
    proc_entry = proc_create("kmon", 0666, NULL, &kmon_proc_ops);
    if (!proc_entry) {
        pr_err("kmon: Failed to create proc entry\n");
        return -ENOMEM;
    }
    
    pr_info("kmon: Proc interface created at /proc/kmon\n");
    return 0;
}

void cleanup_proc_interface(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
        pr_info("kmon: Proc interface removed\n");
    }
}
