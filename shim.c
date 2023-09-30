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

#include "userlib.h"

#define MAX_PATH_LEN 4096 // Max length of the full file path

// We use the below prefix to filter I/O accesses going to the NVMe device
// Change the path to the directory that the device is mounted on
const char DEVICE_DIR[20] = "/mnt/nvme";

int shim_do_open(char* filename, int flags, mode_t mode, int* result) {
    char fullpath[MAX_PATH_LEN];
    int  ret = 0;

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

    // Open the file with BypassD interface if the file is in the device directory
    if (strstr(fullpath, DEVICE_DIR) != NULL) {
        ret = bypassd_open(fullpath, flags, mode, result);
    } else {
        *result = syscall_no_intercept(SYS_open, filename, flags, mode);
    }

    userlib_log("[%s]: filename=%s res=%d\n", __func__, filename, *result);
    return ret;
}

int shim_do_openat(int dfd, char* filename, int flags, mode_t mode, int* result) {
    char fullpath[MAX_PATH_LEN];
    int  ret = 0;

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
        // TODO: Need to handle relative openat
        userlib_log("[%s]: Don't know how to handle relative openat\n", __func__);
        *result = syscall_no_intercept(SYS_openat, dfd, filename, flags, mode);
        return 0;
    }

    // Open the file with BypassD interface if the file is in the device directory
    if (strstr(fullpath, DEVICE_DIR) != NULL) {
        ret = bypassd_open(fullpath, flags, mode, result);
    } else {
        *result = syscall_no_intercept(SYS_openat, dfd, filename, flags, mode);
    }

    userlib_log("[%s]: dfd=%d filename=%s flags=0x%x\n", __func__, dfd, filename, flags);
    return ret;
}

int shim_do_close(int fd, int* result) {
    struct bypassd_file *fp;
    bool   opened;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        bypassd_close(fd, result);
    } else { // Not opened with BypassD interface
        *result = syscall_no_intercept(SYS_close, fd);
    }

    return 0;
}

int shim_do_read(int fd, void* buf, size_t count, size_t* result) {
    struct bypassd_file *fp;
    off_t  offset;
    bool   opened;
    int    ret;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        offset = atomic_load(&fp->offset);
        ret = bypassd_read(fp, buf, count, offset, result);
        if (ret == 0) {
            atomic_fetch_add(&fp->offset, *result);
        } else {
            userlib_log("[%s]: failed\n", __func__);
            *result = 0;
        }
    } else { // Not opened with BypassD interface
        *result = syscall_no_intercept(SYS_read, fd, buf, count);
    }

    userlib_log("[%s]: fd=%d size=%ld\n", __func__, fd, count);
    return 0;
}

int shim_do_pread64(int fd, void* buf, size_t count, loff_t offset, size_t* result) {
    struct bypassd_file *fp;
    bool   opened;
    int    ret;

    userlib_log("[%s]: fd=%d size=%ld, offset=%ld\n", __func__, fd, count, offset);
    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        ret = bypassd_read(fp, buf, count, offset, result);
        if (ret != 0)  {
            userlib_log("[%s]: failed\n", __func__);
        }
    } else { // Not opened with BypassD interface
        *result = syscall_no_intercept(SYS_pread64, fd, buf, count, offset);
    }

    return 0;
}

int shim_do_write(int fd, void* buf, size_t count, size_t* result) {
    struct bypassd_file *fp;
    off_t  offset;
    bool   opened;
    int    ret;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        offset = atomic_load(&fp->offset);
        userlib_log("[%s]: fd=%d size=%ld\n", __func__, fd, count);
        ret = bypassd_write(fp, buf, count, offset, result);
        if (ret == 0) {
            atomic_fetch_add(&fp->offset, *result);
        }
    } else {
        *result = syscall_no_intercept(SYS_write, fd, buf, count);
    }

    return 0;
}

int shim_do_pwrite64(int fd, void* buf, size_t count, loff_t offset, size_t* result) {
    struct bypassd_file *fp;
    bool   opened;
    int    ret;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        userlib_log("[%s]: fd=%d size=%ld offset=%ld\n", __func__, fd, count, offset);
        ret = bypassd_write(fp, buf, count, offset, result);
        if (ret != 0) {
            assert(0);
        }
    } else {
        *result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset);
    }

    return 0;
}

int shim_do_lseek(int fd, off_t offset, int whence, off_t* result) {
    struct bypassd_file *fp;
    bool   opened;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        bypassd_lseek(fp, offset, whence, result);
    } else {
        *result = syscall_no_intercept(SYS_lseek, fd, offset, whence);
    }

    return 0;
}

int shim_do_fallocate(int fd, int mode, off_t offset, off_t len, int* result) {
    struct bypassd_file *fp;
    bool   opened = 0;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        bypassd_fallocate(fp, mode, offset, len, result);
    } else {
        *result = syscall_no_intercept(SYS_fallocate, fd, mode, offset, len);
    }

    return 0;
}

int shim_do_ftruncate(int fd, off_t length, int* result) {
    struct bypassd_file *fp;
    bool   opened = 0;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        bypassd_ftruncate(fp, length, result);
    } else {
        *result = syscall_no_intercept(SYS_ftruncate, fd, length);
    }

    return 0;
}

int shim_do_fdatasync(int fd, int* result) {
    struct bypassd_file *fp;
    bool   opened = 0;

    fp     = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        // If all queues are empty, then we can skip bypassd_fdatasync()
        if (fp->data_modified) {
            bypassd_fdatasync();
            fp->data_modified = false;
        }
        *result = 0;
    } else {
        *result = syscall_no_intercept(SYS_fdatasync, fd);
    }

    return 0;
}

int shim_do_fsync(int fd, int* result) {
    struct bypassd_file *fp;
    bool   opened = 0;

    fp    = &bypassd_info->bypassd_open_files[fd];
    opened = fp->opened;

    if (opened) {
        if (fp->metadata_modified) {
            *result = syscall_no_intercept(SYS_fsync, fd);
            if (*result == 0) {
                fp->metadata_modified = false;
            }
        } else {
            *result = 0;
        }
        if (fp->data_modified) {
            bypassd_fdatasync();
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

    ret = bypassd_init();
    if (ret != 0) {
        fprintf(stderr, "Error initializating library\n");
        return;
    }

    // Set up callback function when syscall intercepted
    intercept_hook_point = &syscall_hook;
}

static __attribute__((destructor)) void finalize(void) {

    userlib_log("Exiting library\n");

    bypassd_exit();
    fclose(logFile);
}
