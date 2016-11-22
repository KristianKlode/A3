#include "lib.h"

void main(void){
  char* buffer[20];
  syscall_read(0,buffer,20);
  uint64_t length = strlen(*buffer);
  syscall_write(1,buffer,length);
}
