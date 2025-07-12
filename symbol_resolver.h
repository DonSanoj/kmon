#ifndef SYMBOL_RESOLVER_H
#define SYMBOL_RESOLVER_H

#include "kmon.h"

// Function pointer for kallsyms_lookup_name
extern unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

// Function declarations
int get_kallsyms_lookup_name(void);
int find_syscall_table(void);

#endif /* SYMBOL_RESOLVER_H */