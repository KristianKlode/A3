/// System calls.

#include <cswitch.h>
#include "proc/syscall.h"
#include "kernel/halt.h"
#include "kernel/panic.h"
#include "lib/libc.h"
#include "kernel/assert.h"
#include "vm/memory.h"
#include "proc/process.h"

/// Handle system calls. Interrupts are enabled when this function is
/// called.
uintptr_t syscall_entry(uintptr_t syscall,
                        uintptr_t arg0, uintptr_t arg1, uintptr_t arg2)
{
  uintptr_t retval = 0;

  // arg0, arg1, and arg2 are unused (for now). Remove this when they do get
  // used below.
  arg0 = arg0;
  arg1 = arg1;
  arg2 = arg2;

  // Handle a userland system call. Before entering this function the userland
  // context has been saved to user_context and after returning from this
  // function the userland context will be restored from user_context.

  switch(syscall) {
  case SYSCALL_HALT:
    kprintf("CALLED syscall halt_kernel\n");
    halt_kernel();
    break;

  case SYSCALL_READ:
    syscall_read(arg0, arg1, arg2);
    break;

  case SYSCALL_WRITE:
    syscall_write(arg0, arg1, arg2);
    break;

  default:
    KERNEL_PANIC("Unhandled system call\n");
  }

  return retval;
}
