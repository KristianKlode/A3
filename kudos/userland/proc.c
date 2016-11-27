#include "lib.h"
#include "halt.c"

void main(void){
syscall_spawn(halt, 0);
syscall_getpid();
/*syscall_spawn(initprog, 0);*/
}
