#include "monitor.h"
#include "hash_ops.h"

void monitor_syscall_table(struct timer_list *timer)
{
    unsigned char current_hash[HASH_LENGTH];
    bool is_anomaly = false;
    int i;
    
    if (!monitoring_enabled)
        goto reschedule;
    
    if (hash_syscall_table_to_buffer(current_hash) != 0) {
        pr_err("kmon: Failed to compute hash during monitoring\n");
        goto reschedule;
    }
    
    // Check against baseline (first hash)
    if (hash_count > 0) {
        if (!compare_hashes(current_hash, hash_history[0].hash)) {
            is_anomaly = true;
            pr_alert("kmon: INTEGRITY VIOLATION DETECTED! Syscall table modified!\n");
            
            pr_info("kmon: Current hash: ");
            for (i = 0; i < HASH_LENGTH; i++)
                pr_cont("%02x", current_hash[i]);
            pr_cont("\n");
        }
    }
    
    store_hash_entry(current_hash, false, is_anomaly);
    
reschedule:
    // Reschedule the timer
    mod_timer(&monitor_timer, jiffies + msecs_to_jiffies(MONITOR_INTERVAL_SEC * 1000));
}

int start_monitoring(void)
{
    // Initialize and start monitoring timer
    timer_setup(&monitor_timer, monitor_syscall_table, 0);
    mod_timer(&monitor_timer, jiffies + msecs_to_jiffies(MONITOR_INTERVAL_SEC * 1000));
    
    pr_info("kmon: Monitoring started\n");
    return 0;
}

void stop_monitoring(void)
{
    // Clean up timer
    del_timer_sync(&monitor_timer);
    pr_info("kmon: Monitoring stopped\n");
}
