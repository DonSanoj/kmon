#ifndef KMON_H
#define KMON_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <asm/unistd.h>

// Constants
#define HASH_LENGTH 32
#define MAX_HASH_HISTORY 100
#define MONITOR_INTERVAL_SEC 60

// Structure definitions
struct hash_entry {
    unsigned char hash[HASH_LENGTH];
    struct timespec64 timestamp;
    bool is_baseline;
    bool is_anomaly;
};

// Global variables (declared here, defined in main module)
extern unsigned long **syscall_table;
extern struct hash_entry hash_history[MAX_HASH_HISTORY];
extern int hash_count;
extern int current_index;
extern struct timer_list monitor_timer;
extern struct proc_dir_entry *proc_entry;
extern bool monitoring_enabled;

// Function declarations
int get_kallsyms_lookup_name(void);
int find_syscall_table(void);
int hash_syscall_table_to_buffer(unsigned char *hash_output);
void store_hash_entry(unsigned char *hash, bool is_baseline, bool is_anomaly);
bool compare_hashes(unsigned char *hash1, unsigned char *hash2);
void monitor_syscall_table(struct timer_list *timer);

#endif /* KMON_H */