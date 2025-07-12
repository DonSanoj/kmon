#include "kmon.h"
#include "symbol_resolver.h"
#include "hash_ops.h"
#include "monitor.h"
#include "proc_interface.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sanoj");
MODULE_DESCRIPTION("Kernel Integrity Monitor with Real-Time Monitoring");

// Global variable definitions
unsigned long **syscall_table;
struct hash_entry hash_history[MAX_HASH_HISTORY];
int hash_count = 0;
int current_index = 0;
struct timer_list monitor_timer;
struct proc_dir_entry *proc_entry;
bool monitoring_enabled = true;

static int __init kmon_init(void)
{
    unsigned char baseline_hash[HASH_LENGTH];
    int ret;
    
    pr_info("kmon: Module loaded\n");

    // Find syscall table
    ret = find_syscall_table();
    if (ret < 0) {
        pr_err("kmon: Failed to locate sys_call_table\n");
        return ret;
    }

    // Create proc interface
    ret = create_proc_interface();
    if (ret < 0) {
        pr_err("kmon: Failed to create proc interface\n");
        return ret;
    }

    // Compute and store baseline hash
    ret = hash_syscall_table_to_buffer(baseline_hash);
    if (ret == 0) {
        store_hash_entry(baseline_hash, true, false);
        pr_info("kmon: Baseline hash established\n");
    } else {
        pr_err("kmon: Failed to establish baseline hash\n");
        cleanup_proc_interface();
        return ret;
    }

    // Start monitoring
    ret = start_monitoring();
    if (ret < 0) {
        pr_err("kmon: Failed to start monitoring\n");
        cleanup_proc_interface();
        return ret;
    }
    
    pr_info("kmon: Real-time monitoring started (interval: %d seconds)\n", MONITOR_INTERVAL_SEC);
    pr_info("kmon: Use 'cat /proc/kmon' to view hash history\n");
    pr_info("kmon: Use 'echo start/stop/clear > /proc/kmon' to control monitoring\n");

    return 0;
}

static void __exit kmon_exit(void)
{
    stop_monitoring();
    cleanup_proc_interface();
    pr_info("kmon: Module unloaded\n");
}

module_init(kmon_init);
module_exit(kmon_exit);
