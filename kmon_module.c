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
#include <asm/unistd.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sanoj");
MODULE_DESCRIPTION("Kernel Integrity Monitor - Step 1");

unsigned long **syscall_table;

#define HASH_LENGTH 32 // SHA-256 outputs 32 bytes

// Function to get kallsyms_lookup_name address using kprobe
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static int get_kallsyms_lookup_name(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    
    if (register_kprobe(&kp) < 0) {
        pr_err("KIM: Failed to register kprobe\n");
        return -1;
    }
    
    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);
    
    return 0;
}

static int find_syscall_table(void)
{
    // Get kallsyms_lookup_name function pointer
    if (get_kallsyms_lookup_name() < 0) {
        pr_err("KIM: Failed to get kallsyms_lookup_name\n");
        return -1;
    }
    
    // Look up the system call table
    syscall_table = (unsigned long **)kallsyms_lookup_name_ptr("sys_call_table");
    
    if (!syscall_table) {
        pr_err("KIM: Failed to find sys_call_table\n");
        return -1;
    }
    
    pr_info("KIM: Found sys_call_table at address: %px\n", syscall_table);
    return 0;
}

static int hash_syscall_table(void)
{
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    unsigned char *digest;
    void *table_copy;
    int i, ret;

    size_t table_size = sizeof(void *) * NR_syscalls;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("KIM: crypto_alloc_shash failed\n");
        return PTR_ERR(tfm);
    }

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    digest = kmalloc(HASH_LENGTH, GFP_KERNEL);
    table_copy = kmalloc(table_size, GFP_KERNEL);

    if (!shash || !digest || !table_copy)
    {
        pr_err("KIM: Memory allocation failed\n");
        ret = -ENOMEM;
        goto free_all;
    }

    memcpy(table_copy, syscall_table, table_size);

    shash->tfm = tfm;
    // shash->flags = 0;  // No longer used in newer kernels

    ret = crypto_shash_init(shash);
    ret |= crypto_shash_update(shash, table_copy, table_size);
    ret |= crypto_shash_final(shash, digest);

    if (ret)
    {
        pr_err("KIM: Hashing failed\n");
        goto free_all;
    }

    pr_info("KIM: SHA-256 hash of syscall table:\n");
    for (i = 0; i < HASH_LENGTH; i++)
        pr_cont("%02x", digest[i]);
    pr_cont("\n");

free_all:
    kfree(shash);
    kfree(digest);
    kfree(table_copy);
    crypto_free_shash(tfm);
    return ret;
}

static int __init kim_init(void)
{
    pr_info("KIM: Module loaded\n");

    // Dynamically find syscall table instead of hardcoding
    if (find_syscall_table() < 0) {
        pr_err("KIM: Failed to locate sys_call_table\n");
        return -1;
    }

    hash_syscall_table();
    return 0;
}

static void __exit kim_exit(void)
{
    pr_info("KIM: Module unloaded\n");
}

module_init(kim_init);
module_exit(kim_exit);
