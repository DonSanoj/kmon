#include "hash_ops.h"

int hash_syscall_table_to_buffer(unsigned char *hash_output)
{
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    void *table_copy;
    int ret;
    size_t table_size = sizeof(void *) * NR_syscalls;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("kmon: crypto_alloc_shash failed\n");
        return PTR_ERR(tfm);
    }

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    table_copy = kmalloc(table_size, GFP_KERNEL);

    if (!shash || !table_copy) {
        pr_err("kmon: Memory allocation failed\n");
        ret = -ENOMEM;
        goto cleanup;
    }

    memcpy(table_copy, syscall_table, table_size);
    shash->tfm = tfm;

    ret = crypto_shash_init(shash);
    ret |= crypto_shash_update(shash, table_copy, table_size);
    ret |= crypto_shash_final(shash, hash_output);

    if (ret) {
        pr_err("kmon: Hashing failed\n");
    }

cleanup:
    kfree(shash);
    kfree(table_copy);
    crypto_free_shash(tfm);
    return ret;
}

void store_hash_entry(unsigned char *hash, bool is_baseline, bool is_anomaly)
{
    struct hash_entry *entry = &hash_history[current_index];
    
    memcpy(entry->hash, hash, HASH_LENGTH);
    ktime_get_real_ts64(&entry->timestamp);
    entry->is_baseline = is_baseline;
    entry->is_anomaly = is_anomaly;
    
    current_index = (current_index + 1) % MAX_HASH_HISTORY;
    if (hash_count < MAX_HASH_HISTORY)
        hash_count++;
}

bool compare_hashes(unsigned char *hash1, unsigned char *hash2)
{
    return memcmp(hash1, hash2, HASH_LENGTH) == 0;
}
