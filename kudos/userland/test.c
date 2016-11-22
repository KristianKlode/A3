/*
 * Halt the system from userland.
 */

#include "lib.h"

int main(void) {
  _syscall(0x142, 0, 0, 0);
  syscall_halt();
  return 0;
}
