#include "symbol_resolver.h"

// Function pointer for kallsyms_lookup_name
unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

int get_kallsyms_lookup_name(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    
    if (register_kprobe(&kp) < 0) {
        pr_err("kmon: Failed to register kprobe\n");
        return -1;
    }
    
    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);
    
    return 0;
}

int find_syscall_table(void)
{
    // Get kallsyms_lookup_name function pointer
    if (get_kallsyms_lookup_name() < 0) {
        pr_err("kmon: Failed to get kallsyms_lookup_name\n");
        return -1;
    }
    
    // Look up the system call table
    syscall_table = (unsigned long **)kallsyms_lookup_name_ptr("sys_call_table");
    
    if (!syscall_table) {
        pr_err("kmon: Failed to find sys_call_table\n");
        return -1;
    }
    
    pr_info("kmon: Found sys_call_table at address: %px\n", syscall_table);
    return 0;
}
