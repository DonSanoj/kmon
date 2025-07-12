#ifndef MONITOR_H
#define MONITOR_H

#include "kmon.h"

// Function declarations
void monitor_syscall_table(struct timer_list *timer);
int start_monitoring(void);
void stop_monitoring(void);

#endif /* MONITOR_H */