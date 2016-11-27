#include "lib.h"
#import "halt"

void main(void){

syscall_spawn(halt, 0);
syscall_getpid();
/*syscall_spawn(initprog, 0);*/
}
