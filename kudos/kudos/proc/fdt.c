/// File desriptor tables.

#include "fs/vfs.h"
#include "kernel/klock.h"
#include "proc/fdt.h"
#include "proc/process.h"

klock_t fdt_lock;

#define FDT_MAX_TABLES (PROCESS_MAX_PROCESSES)

fdt_t fdts[FDT_MAX_TABLES];

void fdt_init() {
  size_t i, j;

  klock_init(&fdt_lock);

  for (i = 0; i < FDT_MAX_TABLES; i++) {
    fdts[i].state = FDT_FREE;
    for (j = 0; j < FDT_MAX_FILES; j++) {
      fdts[i].files[j] = -1;
    }
    fdts[i].nfiles = 0;
    klock_init(&fdts[i].lock);
  }
}

fdt_id_t fdt_alloc() {
  size_t i;

  klock_status_t st = klock_lock(&fdt_lock);

  for (i = 0; i < FDT_MAX_TABLES; i++) {
    if (fdts[i].state == FDT_FREE) {
      fdts[i].state = FDT_TAKEN;
    }
  }

  klock_open(st, &fdt_lock);

  return i;
}

openfile_t fdt_open(fdt_t *fdt, const char *path) {
  size_t i;
  openfile_t ret_fd;

  klock_status_t st = klock_lock(&fdt->lock);

  if (fdt->nfiles >= FDT_MAX_FILES) {
    klock_open(st, &fdt_lock);
    return VFS_ERROR;
  }

  openfile_t fd = vfs_open(path);
  if (fd < 0) {
    klock_open(st, &fdt_lock);
    return fd;
  }

  for (i = 0; i < FDT_MAX_FILES; i++) {
    if (fdt->files[i] < 0) {
      fdt->files[i] = fd;
    }
  }

  ret_fd = fdt->nfiles++;
  ret_fd += 2; // Account for stdin, stdout, stderr.

  klock_open(st, &fdt_lock);

  return ret_fd;
}

int fdt_read(fdt_t *fdt, openfile_t fd, void *buf, size_t nbytes) {
  if (fdt <= 2) {
    return VFS_NOT_SUPPORTED;
  } else {
    return vfs_read(fdt->files[fd - 2], buf, nbytes);
  }
}

int fdt_write(fdt_t *fdt, openfile_t fd, const void *buf, size_t nbytes) {
  if (fdt <= 2) {
    return VFS_NOT_SUPPORTED;
  } else {
    return vfs_write(fdt->files[fd - 2], buf, nbytes);
  }
}
