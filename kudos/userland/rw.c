#include "lib.h"

static const size_t BUFFER_SIZE = 20;

void main(void){
  char *name;
  heap_init();
  name = (char*)malloc(BUFFER_SIZE);
  syscall_read(0,name,20);
  uint64_t length = strlen(name);
  syscall_write(1,name,length);
}
