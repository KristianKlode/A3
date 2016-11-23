/// Kernel support for userland processes.

#ifndef KUDOS_PROC_PROCESS_H
#define KUDOS_PROC_PROCESS_H

#include "lib/types.h"
#include "vm/memory.h"

#define PROCESS_PTABLE_FULL  (-1)
#define PROCESS_ILLEGAL_JOIN (-2)
#define PROCESS_ERROR_FILEHANDLER (-3)
#define PROCESS_ERROR_NO_SUCH_PROCESS (-4)

#define PROCESS_MAX_FILELENGTH (256)
#define PROCESS_MAX_PROCESSES  (128)
#define PROCESS_MAX_FILES      (10)

typedef int pid_t;

enum process_state {FREE, TAKEN, WAIT};

typedef struct {
  // TODO: Define a pid namespace here.
  enum process_state state;
  pid_t pid;
  char path;
  TID_t tid;
} pcb_t;

void process_start(const char *path);
int syscall_read(int fd, void *buf, uint64_t nbytes);
int syscall_write(int fd, void const *buf, uint64_t nbytes);

#endif // KUDOS_PROC_PROCESS_H
