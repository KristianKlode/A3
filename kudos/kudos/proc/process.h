/// Kernel support for userland processes.

#ifndef KUDOS_PROC_PROCESS_H
#define KUDOS_PROC_PROCESS_H

#include "lib/types.h"
#include "vm/memory.h"
#include "kernel/thread.h"
#include "kernel/types.h"

#define PROCESS_PTABLE_FULL  (-1)
#define PROCESS_ILLEGAL_JOIN (-2)
#define PROCESS_ERROR_FILEHANDLER (-3)
#define PROCESS_ERROR_NO_SUCH_PROCESS (-4)
#define PROCESS_ERROR_NO_SUCH_FLAG (-5)

#define PROCESS_MAX_FILELENGTH (256)
#define PROCESS_MAX_PROCESSES  (128)
#define PROCESS_MAX_FILES      (10)

enum process_state {FREE, TAKEN, WAIT};

typedef struct {
  // TODO: Define a pid namespace here.
  enum process_state state;
  pid_t pid;
  pid_t fakepid;
  char path;
  TID_t tid;
} pcb_t;

void process_start(TID_t tid);
int syscall_read(int fd, void *buf, uint64_t nbytes);
int syscall_write(int fd, void const *buf, uint64_t nbytes);


#endif // KUDOS_PROC_PROCESS_H
