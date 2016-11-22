/// System calls.

#ifndef KUDOS_PROC_SYSCALL_H
#define KUDOS_PROC_SYSCALL_H

// Syscall function numbers. You may add to this list but do not
// modify the existing ones.

#define SYSCALL_HALT      (0x001)

#define SYSCALL_GETPID    (0x100)
#define SYSCALL_SPAWN     (0x101)
#define SYSCALL_EXIT      (0x102)
#define SYSCALL_JOIN      (0x103)
#define SYSCALL_FORK      (0x104)
#define SYSCALL_MEMLIMIT  (0x105)

#define SYSCALL_OPEN      (0x201)
#define SYSCALL_CLOSE     (0x202)
#define SYSCALL_SEEK      (0x203)
#define SYSCALL_READ      (0x204)
#define SYSCALL_WRITE     (0x205)
#define SYSCALL_CREATE    (0x206)
#define SYSCALL_DELETE    (0x207)
#define SYSCALL_FILECOUNT (0x208)
#define SYSCALL_FILE      (0x209)

#define SPAWN_NEWPIDNS    (0x1)
#define SPAWN_OLDFDT      (0x2)

// When userland program reads or writes these already open files it
// actually accesses the console.

#define FD_STDIN  (0)
#define FD_STDOUT (1)
#define FD_STDERR (2)

#endif // KUDOS_PROC_SYSCALL_H
