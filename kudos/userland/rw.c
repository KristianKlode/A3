#include "lib.h"

void rw(void){
  buffer = "Hello world!"
  length = strlen(buffer)
  syscall_write(1,*buffer,length);
  return 0;
}
