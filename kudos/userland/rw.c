#include "lib.h"

void main(void){
  char* buffer = "Hello world!";
  uint64_t length = strlen(buffer);
  syscall_write(1,buffer,length);
}
