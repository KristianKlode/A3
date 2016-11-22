/// Kernel support for userland processes.

#ifndef KUDOS_PROC_PROCESS_H
#define KUDOS_PROC_PROCESS_H

#include "lib/types.h"
#include "vm/memory.h"

#define PROCESS_PTABLE_FULL  (-1)
#define PROCESS_ILLEGAL_JOIN (-2)

#define PROCESS_MAX_FILELENGTH (256)
#define PROCESS_MAX_PROCESSES  (128)
#define PROCESS_MAX_FILES      (10)

typedef int pid_t;

typedef struct {
  // TODO: Define a pid namespace here.
  pid_t pid;
} pcb_t;

void process_start(const char *path);
int syscall_read(int fd, void *buf, uint64_t nbytes);
int syscall_write(int fd, void const *buf, uint64_t nbytes);

#endif // KUDOS_PROC_PROCESS_H
