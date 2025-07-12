#ifndef HASH_OPS_H
#define HASH_OPS_H

#include "kmon.h"

// Function declarations
int hash_syscall_table_to_buffer(unsigned char *hash_output);
void store_hash_entry(unsigned char *hash, bool is_baseline, bool is_anomaly);
bool compare_hashes(unsigned char *hash1, unsigned char *hash2);

#endif /* HASH_OPS_H */