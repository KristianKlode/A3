/// File desriptor tables.

#ifndef KUDOS_PROC_FDT_H
#define KUDOS_PROC_FDT_H

#include "fs/vfs.h"
#include "kernel/config.h"
#include "kernel/klock.h"
#include "lib/types.h"

typedef size_t fdt_id_t;

#define FDT_MAX_FILES (CONFIG_MAX_OPEN_FILES)

enum fdt_state { FDT_FREE, FDT_TAKEN };

typedef struct {
  enum fdt_state state;
  klock_t lock;
  openfile_t files[FDT_MAX_FILES];
  size_t nfiles;
} fdt_t;

void fdt_init(void);

fdt_id_t fdt_alloc(void);

openfile_t fdt_open(fdt_t *fdt, const char *path);
int fdt_read(fdt_t *fdt, openfile_t fd, void *buf, size_t nbytes);
int fdt_write(fdt_t *fdt, openfile_t fd, const void *buf, size_t nbytes);

#endif // KUDOS_PROC_FDT_H
