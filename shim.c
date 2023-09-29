#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <libsyscall_intercept_hook_point.h>

#include "sw_lib.h"

#define PATH_SIZE 4096
const char DEVICE_DIR[20] = "/mnt/nvme";

double total_avg = 0;
int total_count = 0;
__thread struct timespec total_start, total_end;

int shim_do_open(char* filename, int flags, mode_t mode, int* result) {
    char fullpath[PATH_SIZE];
    int ret = 0;

    memset(fullpath, 0, sizeof(fullpath));

    if (filename[0] == '/') {
        strcpy(fullpath, filename);
    } else {
        if(getcwd(fullpath, sizeof(fullpath)) == NULL) {
            return 1;
        }
        strcat(fullpath, "/");
        strcat(fullpath, filename);
    }

    if (strstr(fullpath, DEVICE_DIR) != NULL) {
        ret = sw_open(fullpath, flags, mode, result);
    } else {
        *result = syscall_no_intercept(SYS_open, filename, flags, mode);
    }

    sw_log("[OPEN]: filename=%s res=%d\n", filename, *result);
    return ret;
}

int shim_do_openat(int dfd, char* filename, int flags, mode_t mode, int* result) {
    char fullpath[PATH_SIZE];
    int ret = 0;

    memset(fullpath, 0, sizeof(fullpath));

    if (filename[0] == '/') {
        strcpy(fullpath, filename);
    } else if (dfd == AT_FDCWD) {
        if (getcwd(fullpath, sizeof(fullpath)) == NULL) {
            return 1;
        }
        strcat(fullpath, "/");
        strcat(fullpath, filename);
    } else {
        sw_log("[OPENAT]: Don't know how to handle relative openat\n");
        *result = syscall_no_intercept(SYS_openat, dfd, filename, flags, mode);
        return 0;
    }

    if (strstr(fullpath, DEVICE_DIR) != NULL) {
        ret = sw_open(fullpath, flags, mode, result);
    } else {
        *result = syscall_no_intercept(SYS_openat, dfd, filename, flags, mode);
    }

    sw_log("[OPENAT]: dfd=%d filename=%s flags=0x%x\n", dfd, filename, flags);
    return ret;
}

int shim_do_close(int fd, int* result) {
    struct sw_file *fp;
    bool opened;

    fp = &sw_info->sw_open_files[fd];
    opened = fp->opened;

    if (opened) {
        sw_close(fd, result);
    } else { // Not opened with SW interface
        *result = syscall_no_intercept(SYS_close, fd);
    }

    return 0;
}

int shim_do_read(int fd, void* buf, size_t count, size_t* result) {
    struct sw_file *fp;
    off_t offset;
    bool opened;
    int ret;

    clock_gettime(CLOCK_REALTIME, &total_start);
    sw_log("[READ]: fd=%d size=%ld\n", fd, count);
    fp = &sw_info->sw_open_files[fd];

    opened = fp->opened;

    if (opened) {
        offset = atomic_load(&fp->offset);
        ret = sw_read(fp, buf, count, offset, result);
        if (ret == 0) {
            atomic_fetch_add(&fp->offset, *result);
        } else {
            sw_log("[READ]: failed\n");
            *result = 0;
        }
    } else { // Not opened with SW interface
        *result = syscall_no_intercept(SYS_read, fd, buf, count);
    }

    clock_gettime(CLOCK_REALTIME, &total_end);
    total_avg += (total_end.tv_sec - total_start.tv_sec) * 1e6 + (total_end.tv_nsec - total_start.tv_nsec) / 1e3;
    total_count++;
    return 0;
}

int shim_do_pread64(int fd, void* buf, size_t count, loff_t offset, size_t* result) {
    struct sw_file *fp;
    bool opened;
    int ret;

    clock_gettime(CLOCK_REALTIME, &total_start);
    sw_log("[PREAD64]: fd=%d size=%ld, offset=%ld\n", fd, count, offset);
    fp = &sw_info->sw_open_files[fd];

    opened = fp->opened;

    if (opened) {
        ret = sw_read(fp, buf, count, offset, result);
        if (ret != 0)  {
            sw_log("[PREAD64]: failed\n");
        }
    } else { // Not opened with SW interface
        *result = syscall_no_intercept(SYS_pread64, fd, buf, count, offset);
    }
    clock_gettime(CLOCK_REALTIME, &total_end);
    total_avg += (total_end.tv_sec - total_start.tv_sec) * 1e6 + (total_end.tv_nsec - total_start.tv_nsec) / 1e3;
    total_count++;
    return 0;
}

int shim_do_write(int fd, void* buf, size_t count, size_t* result) {
    struct sw_file *fp;
    off_t offset;
    bool opened;
    int ret;

    fp = &sw_info->sw_open_files[fd];
    opened = fp->opened;

    if (opened) {
        offset = atomic_load(&fp->offset);
        sw_log("[WRITE]: fd=%d size=%ld\n", fd, count);
        ret = sw_write(fp, buf, count, offset, result);
        if (ret == 0) {
            atomic_fetch_add(&fp->offset, *result);
        }
    } else {
        *result = syscall_no_intercept(SYS_write, fd, buf, count);
    }

    return 0;
}

int shim_do_pwrite64(int fd, void* buf, size_t count, loff_t offset, size_t* result) {
    struct sw_file *fp;
    bool opened;
    int ret;

    fp = &sw_info->sw_open_files[fd];
    opened = fp->opened;

    if (opened) {
        sw_log("[PWRITE64]: fd=%d size=%ld offset=%ld\n", fd, count, offset);
        ret = sw_write(fp, buf, count, offset, result);
        if (ret != 0) {
            assert(0);
        }
    } else {
        *result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset);
    }

    return 0;
}

int shim_do_lseek(int fd, off_t offset, int whence, off_t* result) {
    struct sw_file *fp;
    bool opened;

    fp = &sw_info->sw_open_files[fd];
    opened = fp->opened;

    if (opened) {
        sw_lseek(fp, offset, whence, result);
    } else {
        *result = syscall_no_intercept(SYS_lseek, fd, offset, whence);
    }

    return 0;
}

int shim_do_fallocate(int fd, int mode, off_t offset, off_t len, int* result) {
    struct sw_file *fp;
    bool opened = 0;

    if (fd < MAX_FILES) {
        fp = &sw_info->sw_open_files[fd];
        opened = fp->opened;
    }

    if (opened) {
        sw_fallocate(fp, mode, offset, len, result);
    } else {
        *result = syscall_no_intercept(SYS_fallocate, fd, mode, offset, len);
    }

    return 0;
}

int shim_do_ftruncate(int fd, off_t length, int* result) {
    struct sw_file *fp;
    bool opened = 0;

    if (fd < MAX_FILES) {
        fp = &sw_info->sw_open_files[fd];
        opened = fp->opened;
    }

    if (opened) {
        sw_ftruncate(fp, length, result);
    } else {
        *result = syscall_no_intercept(SYS_ftruncate, fd, length);
    }

    return 0;
}

int shim_do_fdatasync(int fd, int* result) {
    struct sw_file *fp;
    bool opened = 0;

    if (fd < MAX_FILES) {
        fp = &sw_info->sw_open_files[fd];
        opened = fp->opened;
    }

    if (opened) {
        if (fp->data_modified) {
            sw_fdatasync();
            fp->data_modified = false;
        }
        *result = 0;
    } else {
        *result = syscall_no_intercept(SYS_fdatasync, fd);
    }

    return 0;
}

int shim_do_fsync(int fd, int* result) {
    struct sw_file *fp;
    bool opened = 0;

    if (fd < MAX_FILES) {
        fp = &sw_info->sw_open_files[fd];
        opened = fp->opened;
    }

    if (opened) {
        if (fp->metadata_modified) {
            *result = syscall_no_intercept(SYS_fsync, fd);
            if (*result == 0) fp->metadata_modified = false;
        } else {
            *result = 0;
        }
        if (fp->data_modified) {
            sw_fdatasync();
            fp->data_modified = false;
        }
    } else {
        *result = syscall_no_intercept(SYS_fsync, fd);
    }

    return 0;
}

static int syscall_hook(long syscall_number, long arg0, long arg1,
                        long arg2, long arg3, long arg4, long arg5, long *result) {
    switch (syscall_number) {
        case SYS_open:
            return shim_do_open((char*)arg0, (int)arg1, (mode_t)arg2, (int*)result);
        case SYS_openat:
            return shim_do_openat((int)arg0, (char*)arg1, (int)arg2, (mode_t)arg3, (int*)result);
        case SYS_creat:
            break;
        case SYS_close:
            return shim_do_close((int)arg0, (int*)result);
        case SYS_read:
            return shim_do_read((int)arg0, (void*)arg1, (size_t)arg2, (size_t*)result);
        case SYS_pread64:
            return shim_do_pread64((int)arg0, (void*)arg1, (size_t)arg2, (loff_t)arg3, (size_t*)result);
        case SYS_write:
            return shim_do_write((int)arg0, (void*)arg1, (size_t)arg2, (size_t*)result);
        case SYS_pwrite64:
            return shim_do_pwrite64((int)arg0, (void*)arg1, (size_t)arg2, (loff_t)arg3, (size_t*)result);
        case SYS_lseek:
            return shim_do_lseek((int)arg0, (off_t)arg1, (int)arg2, (off_t*)result);
        case SYS_fallocate:
            return shim_do_fallocate((int)arg0, (int)arg1, (off_t)arg2, (off_t)arg3, (int*)result);
        case SYS_ftruncate:
            return shim_do_ftruncate((int)arg0, (off_t)arg1, (int*)result);
        case SYS_fdatasync:
            return shim_do_fdatasync((int)arg0, (int*)result);
        case SYS_fsync:
            return shim_do_fsync((int)arg0, (int*)result);
        case SYS_rename: // do we need this?
        case SYS_truncate:
        case SYS_sync:
        case SYS_fcntl:
        default:
            break;
    }

    return 1;
}

static __attribute__((constructor)) void initialize(void) {
    int ret;

    ret = sw_init();
    if (ret != 0) {
        fprintf(stderr, "Error initializating library\n");
        return;
    }

    // Set up callback function when syscall intercepted
    intercept_hook_point = &syscall_hook;
}

static __attribute__((destructor)) void finalize(void) {

    sw_log("Exiting library\n");

    sw_exit();
    fclose(logFile);
}
