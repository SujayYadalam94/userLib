#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syscall.h>

#include "pa_maps.h"
#include "userlib.h"
#include "mem.h"
#include "nvme.h"

#include <libsyscall_intercept_hook_point.h>

__thread long _tid = 0;

extern double avg;
extern int scount;
extern double total_avg;
extern int total_count;
double bypassd_avg = 0;
int bypassd_count = 0;
__thread struct timespec bypassd_start,bypassd_end;

int bypassd_initialized = 0;

#ifdef DEBUG
void bypassd_log(const char *fmt, ...) {
    char date[20];
    struct timeval tv;
    va_list args;

    gettimeofday(&tv, NULL);
    strftime(date, sizeof(date) / sizeof(*date), "%H:%M:%S", gmtime(&tv.tv_sec));
    fprintf(logFile, "[%s.%03ld] ", date, tv.tv_usec);

    va_start(args, fmt);
    vfprintf(logFile, fmt, args);
    va_end(args);
}
#endif

long bypassd_gettid() {
    if (!_tid) {
        _tid = syscall_no_intercept(SYS_gettid);
    }

    return _tid;
}
// TODO: Implement user page caching

/*****************************************************************************/

int bypassd_create_queues(int num_queues) {
    struct bypassd_queue *queue;
    struct bypassd_ioctl_queue_info *iq;
    int i;
    int ret;

    iq = malloc(sizeof(*iq));

    for (i=0; i<num_queues; i++) {
        queue = malloc(sizeof(*queue));
        ret = ioctl(bypassd_info->i_fd, IOCTL_CREATE_QUEUE_PAIR, iq);
        if (ret != 0) {
            free(queue);
            break;
        }
        memcpy(queue, iq, sizeof(*iq));
        queue->sq_tail = 0;
        queue->cq_head = 0;
        queue->cq_phase = 1;
        bypassd_spinlock_init(&queue->sq_lock);
        bypassd_spinlock_init(&queue->cq_lock);
        queue->rqs = calloc(queue->q_depth, sizeof(struct bypassd_req));
        queue->cmd_id = 0;
        queue->pending_io_writes = 0;
        bypassd_log("[bypassd_create_queues]: %ld: Created queue id=%d\n", bypassd_gettid(), queue->qid);

        bypassd_info->bypassd_queue_list[i] = queue;
    }

    free(iq);
    return i;
}

int bypassd_delete_queues() {
    struct bypassd_queue *queue;
    int i;

    for (i=0; i<bypassd_info->nr_queues; i++) {
        queue = bypassd_info->bypassd_queue_list[i];
        if (queue != NULL) {
            ioctl(bypassd_info->i_fd, IOCTL_DELETE_QUEUE_PAIR, &queue->qid);

            free(queue->rqs);
            free(queue);
        }
    }
    bypassd_info->nr_queues = 0;

    return 0;
}

/*****************************************************************************/

int bypassd_open(char* filename, int flags, mode_t mode, int* result) {
    int fd;
    struct bypassd_file *fp;
    int ret;
    struct stat f_stat;
    unsigned long addr, addr_fast;

    ret = syscall_no_intercept(SYS_stat, filename, &f_stat);
    if (ret == -ENOENT && (flags & O_CREAT)) {
        bypassd_log("[bypassd_open]: File doesn't exist but creating\n");
        f_stat.st_size = 0;
        goto special_open;
    } else if (ret != 0) {
        return 1;
    }

    // Do not open directories
    if (flags & O_DIRECTORY || !S_ISREG(f_stat.st_mode)) {
        return 1;
    }

special_open:
    //fd = syscall_no_intercept(SYS_open, filename, flags, mode);
    fd = syscall(337, -1, filename, flags, mode, &addr, &addr_fast);
    *result = fd;
    if (fd < 0) {
        bypassd_log("[%s]: Special open returned = %d\n", __func__, fd);
        return 0;
    }

    fp = &bypassd_info->bypassd_open_files[fd];

    strcpy(fp->filename, filename);
    fp->size = f_stat.st_size;
    fp->old_fva = addr;
    fp->fva = addr_fast;

    fp->fd = fd;
    fp->offset = 0;
    fp->flags = flags;
    fp->mode = mode;
    fp->append_offset = f_stat.st_size;

    fp->data_modified = false;
    fp->metadata_modified = (flags & O_CREAT)?true:false;

    if (bypassd_info->nr_queues == 0) {
        bypassd_info->nr_queues = bypassd_create_queues(BYPASSD_NUM_QUEUES);
        if (bypassd_info->nr_queues == 0) {
            bypassd_log("[%s]: Failed to create user queues\n", __func__);
            return -1;
        } else {
            bypassd_log("[%s]: Created %d queues\n", __func__, bypassd_info->nr_queues);
        }
    }
    // Per file queue with hashing to handle limited number of queues
    fp->queue = bypassd_info->bypassd_queue_list[fd % bypassd_info->nr_queues];
    fp->ns_info = &bypassd_info->ns_info;

    fp->opened = 1; // File is now open to access by shim library

    bypassd_info->nr_open_files++; // TODO: No use for now

    bypassd_log("[bypassd_open]: tid=%ld filename:%s fd:%d fva:0x%lx\n", bypassd_gettid(), filename, fd, fp->fva);

    return 0;
}

int bypassd_close(int fd, int *result) {
    struct bypassd_file *fp;

    fp = &bypassd_info->bypassd_open_files[fd];
    syscall_no_intercept(338, fd, fp->old_fva, fp->fva);

    // TODO: should we clear struct bypassd_file??
    fp->opened = 0;

    *result = 0;

    bypassd_log("[bypassd_close]: tid=%ld fd=%d\n", bypassd_gettid(), fp->fd);

    return 0;
}

int bypassd_get_lba(struct bypassd_file *fp, size_t len, loff_t offset,
            unsigned long *lba, loff_t *io_size) {
    unsigned long slba;
    unsigned long prev_lba, next_lba;
    loff_t size;

    slba = get_physical_frame_fast((void *)fp->fva, offset/PAGE_SIZE);
    if (slba == 0) {
        bypassd_log("[%s]: get_lba failed @ offset:%ld\n", __func__, offset);
        return 1;
    }
    // TODO: In real BypassD, we don't need to issue multiple IOs, IOMMU will
    //       translate into multiple LBAs. How to measure performance gain?
    // If read spans across multiple LBAs, issue separate IOs
    if (offset < PAGE_ALIGN(offset) && (loff_t)(offset+len) > PAGE_ALIGN(offset)) {
        size = PAGE_ALIGN(offset) - offset;
    } else {
        size = (len < LB_SIZE) ? len : LB_SIZE;

        prev_lba = slba;
        while (size < (loff_t)len) {
            next_lba = get_physical_frame_fast((void *)fp->fva, (offset+size)/PAGE_SIZE);
            if (next_lba == 0) {
                assert(0);
            } else if (next_lba == prev_lba+1) { // Contiguous blocks
                size += (len-size < LB_SIZE)?(len-size):LB_SIZE;
            } else { // Non-contiguous blocks, issue separate IOs
                break;
            }
            prev_lba = next_lba;
        }
    }

    *lba = (slba << 3) + ((offset % PAGE_SIZE)/BLK_SIZE);
    *io_size = size;

    // IMPORTANT: No need of delay if not using BBUF.
    //            The address translation for buffers takes ~1us.
    // Delay emulating ATS latency (PCIe+IOTLB miss)
    // Value should be set based on core frequency
    // For a 3GHz processor, 1800 cycles ~ 600ns
    for (int x=0; x < 0; x++) {
        asm volatile ("nop;" : : : "memory");
    }
    return 0;
}

int bypassd_read(struct bypassd_file *fp, char* buf, size_t len, loff_t offset, size_t* result) {
    size_t file_size;
    unsigned long slba;
    size_t num_blks;
    loff_t cnt, io_size = 0;

    struct bypassd_queue *queue;
    struct bypassd_req *req;

    int ret;

#ifdef DEBUG
    clock_gettime(CLOCK_REALTIME, &bypassd_start);
#endif

    file_size = atomic_load(&fp->size);
    // Invalid offsets
    if (offset < 0 || (size_t)offset > file_size) {
        *result = -EINVAL;
        return 0;
    }

    // Reads to end of file
    if (offset + len > file_size) {
        len = file_size - offset;
    }

    // Make sure read size is greater than 0
    if (len == 0) {
        *result = 0;
        return 0;
    }

#ifdef QUEUE_PER_THREAD
    queue = bypassd_info->bypassd_queue_list[bypassd_gettid() % bypassd_info->nr_queues];
#else
    queue = fp->queue;
#endif

    cnt = len;
    while (cnt > 0) {

        ret = bypassd_get_lba(fp, cnt, offset, &slba, &io_size);
        if (ret == 1) {
            *result = -EINVAL;
            return 0;
        }

        num_blks = (BLK_ALIGN(offset+io_size) - BLK_DOWN_ALIGN(offset)) / BLK_SIZE;

        req = nvme_init_request(queue);
        bypassd_get_buffer(req, buf, io_size, cnt, false);
        if (!req->buf) {
            *result = -ENOMEM;
            return 0;
        }

        nvme_setup_prp(req, PAGE_ALIGN(io_size)/PAGE_SIZE);
        nvme_setup_rw_cmd(req, fp, nvme_cmd_read, slba, num_blks*BLK_SIZE);

        bypassd_log("[bypassd_read]: tid=%lu lba:%llu offset:%llu len:%lu\n", bypassd_gettid(), \
                    req->cmd->slba, offset, req->cmd->length);

        nvme_submit_cmd(queue, req->cmd);
        nvme_poll(queue, req->cmd_id);

        loff_t bytes_read = (io_size<cnt)?io_size:cnt;
        if (!req->buf->user) {
            memcpy(buf, req->buf->vaddr + (offset % BLK_SIZE), bytes_read);
        }

        cnt -= bytes_read;
        offset += bytes_read;
        buf += bytes_read;

        bypassd_put_buffer(req);

#ifdef DEBUG
        clock_gettime(CLOCK_REALTIME, &bypassd_end);
        bypassd_avg += (bypassd_end.tv_sec - bypassd_start.tv_sec) * 1e6 + (bypassd_end.tv_nsec - bypassd_start.tv_nsec) / 1e3;
        bypassd_count++;
#endif
    }

    *result = len;
    return 0;
}

// TODO: Currently do not support unaligned writes and writes smaller than 512B
int bypassd_write(struct bypassd_file *fp, char* buf, size_t len, loff_t offset, size_t* result) {
    size_t file_size;
    struct bypassd_req *req;
    size_t buf_size;
    bool is_append = false;

    unsigned long slba = 0;
    loff_t cnt, io_size = 0;

    struct bypassd_queue *queue;

    int ret;

    file_size = atomic_load(&fp->size);

    if (fp->flags & O_APPEND) {
        is_append = true;
        offset = fp->append_offset;
    }

    // Parameter checks
    if (offset < 0) {
        *result = -EINVAL;
        return 0;
    }

    if (len == 0) {
        *result = 0;
        return 0;
    }

    // Partial writes go through kernel
    if (offset % BLK_SIZE != 0 || len % BLK_SIZE != 0) {
        *result = syscall_no_intercept(SYS_pwrite64, fp->fd, buf, len, offset);
        syscall_no_intercept(SYS_fsync, fp->fd); // Need to persist immediately
        fp->data_modified = false;
        fp->metadata_modified = false;
        return 0;
    }

#ifdef QUEUE_PER_THREAD
    queue = bypassd_info->bypassd_queue_list[bypassd_gettid() % bypassd_info->nr_queues];
#else
    queue = fp->queue;
#endif

    // Appends
    if ((offset + len) > file_size) {
        // TODO: need to handle writes < PAGE_SIZE
#ifdef USE_FALLOCATE_FOR_APPENDS
        ret = syscall_no_intercept(SYS_fallocate, fp->fd, 0, file_size,
                    len * FALLOC_SIZE);
        if (ret == 0) {
            atomic_fetch_add(&fp->size, len * FALLOC_SIZE);
            fp->metadata_modified = true;
        } else {
            *result = ret;
            return 0;
        }
#else
        *result = syscall_no_intercept(SYS_pwrite64, fp->fd, buf, len, offset);
        syscall_no_intercept(SYS_fsync, fp->fd);
        fp->data_modified = false;
        fp->metadata_modified = false;

        if (*result > 0 && (offset + *result) > fp->size) {
            atomic_store(&fp->size, offset + *result); // Increase size of file
        }
        return 0;
#endif
    }

    // Overwrites
    cnt = len;
    while (cnt > 0) {
        ret = bypassd_get_lba(fp, cnt, offset, &slba, &io_size);
        if (ret != 0) {
            bypassd_log("[%s]: Failed to get LBA\n", __func__);
            *result = -EINVAL;
            return 0;
        }

        buf_size = PAGE_ALIGN(io_size);

        req = nvme_init_request(queue);

#ifndef ASYNC_WRITES
        bypassd_get_buffer(req, buf, buf_size, len, false);
        if (!req->buf) {
            *result = -ENOMEM;
            return 0;
        } else if (req->buf->user == 0) {
            memcpy(req->buf->vaddr, buf, io_size);
            memset(req->buf->vaddr + io_size, 0, buf_size - io_size);
        }
#else
       bypassd_get_buffer(req, buf, buf_size, len, true);
        if (!req->buf) {
            *result = -ENOMEM;
            return 0;
        } else {
            memcpy(req->buf->vaddr, buf, io_size);
            memset(req->buf->vaddr + io_size, 0, buf_size - io_size);
        }
#endif
        nvme_setup_prp(req, buf_size/PAGE_SIZE);
        nvme_setup_rw_cmd(req, fp, nvme_cmd_write, slba, io_size);

        bypassd_log("[%s]: Submitting IO: lba:%lld cmdid:%d len:%d\n", __func__, \
                    req->cmd->slba, req->cmd->command_id, req->cmd->length);
#ifndef ASYNC_WRITES
        nvme_submit_cmd(queue, req->cmd);
        nvme_poll(queue, req->cmd_id);
#else
        nvme_process_completions(queue);
        nvme_submit_cmd(queue, req->cmd);
        fp->data_modified = true;
#endif

        cnt -= io_size;
        offset += io_size;
        buf += io_size;
    }
    *result = len;

    if (is_append) {
        fp->append_offset += len;
    }

    return 0;
}

int bypassd_lseek(struct bypassd_file *fp, off_t offset, int whence, off_t* result) {

    switch (whence) {
        case SEEK_END:
            fp->offset = fp->size + offset;
            break;
        case SEEK_CUR:
            fp->offset += offset;
            break;
        case SEEK_SET:
            fp->offset = offset;
            break;
        default:
            *result = -EINVAL;
            return 0; // Invalid whence
            break;
    }

    *result = fp->offset;

    return 0;
}

int bypassd_fallocate(struct bypassd_file *fp, int mode, off_t offset, off_t len, int* result) {

    *result = syscall_no_intercept(SYS_fallocate, fp->fd, mode, offset, len);
    if (*result != 0)
        return 0;

    switch (mode) {
        case 0:
        case FALLOC_FL_KEEP_SIZE:
            atomic_store(&fp->size, offset + len);
            fp->append_offset = fp->size;
            break;
        case FALLOC_FL_COLLAPSE_RANGE:
            atomic_fetch_sub(&fp->size, len); // TODO: need to verify this
            fp->append_offset = fp->size;
            break;
        default:
            break;
    }

    fp->metadata_modified = true;

    return 0;
}

int bypassd_ftruncate(struct bypassd_file *fp, off_t length, int* result) {

    *result = syscall_no_intercept(SYS_ftruncate, fp->fd, length);
    if (*result != 0)
        return 0;

    atomic_store(&fp->size, length);
    fp->metadata_modified = true;

    return 0;
}

void bypassd_fdatasync() {
#ifdef QUEUE_PER_THREAD
    int i;
    struct bypassd_queue *queue;

    for (i=0; i<bypassd_info->nr_queues; i++) {
        queue = bypassd_info->bypassd_queue_list[i];
        if (queue->pending_io_writes) {
            nvme_process_completions(queue);
        }
    }
#else
    while (fp->queue->pending_io_writes) {
        nvme_process_completions(fp->queue);
    }
#endif
}

void bypassd_exit() {
    int i;
    int initialized = 0;

    if (__atomic_compare_exchange_n(&bypassd_initialized, &initialized, 0, false,
                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        bypassd_log("[bypassd_exit]: Already exited\n");
        return;
    }

    bypassd_log("Avg dev latency=%f %f %d\n", avg/scount, avg, scount);
    bypassd_log("Avg software overhead=%f\n", bypassd_avg/bypassd_count);
    bypassd_log("Avg total latency=%f\n", total_avg/total_count);

    bypassd_log("Deleting queues...\n");
    bypassd_delete_queues();
    bypassd_log("Freeing buffers...\n");
    bypassd_release_bounce_buffers();
    bypassd_log("Freeing PRP buffers...\n");
    bypassd_release_prp_buffers();

    bypassd_log("Destroying locks ...\n");
    for (i=0; i<MAX_FILES; ++i) {
        pthread_rwlock_destroy(&bypassd_info->bypassd_open_files[i].file_lock);
    }
    bypassd_log("Exiting..\n");
}

void sig_handler(int sig) {
    bypassd_log("signal_handler: %d\n", sig);
    bypassd_exit();
}

int bypassd_init() {
    int ret;
    int i;
    int initialized = 0;

    if (!__atomic_compare_exchange_n(&bypassd_initialized, &initialized, 1, false,
                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        bypassd_log("[bypassd_init]: Already initialized\n");
        return 0;
    }

    // TODO: which signals to capture?
    signal(SIGUSR1, sig_handler); // for filebench

    logFile = fopen("libshim.log", "w+");

    bypassd_info = (struct bypassd_info*)malloc(sizeof(struct bypassd_info));

    // TODO: How to make it flexible instead of hard-coding?
    bypassd_info->i_fd = syscall_no_intercept(SYS_open, "/proc/bypassd/nvme0n1/ioctl", O_RDWR);
    if (bypassd_info->i_fd <= 0) {
        return -1;
    }

    ret = ioctl(bypassd_info->i_fd, IOCTL_GET_NS_INFO, &bypassd_info->ns_info);
    if (ret != 0) {
        bypassd_log("[bypassd_init]: NS Info IOCTL failed\n");
        return -1;
    }

    bypassd_spinlock_init(&bypassd_info->prp_lock);
    bypassd_spinlock_init(&bypassd_info->buf_lock);
    LIST_INIT(&bypassd_info->bypassd_buf_list);
    LIST_INIT(&bypassd_info->bypassd_prp_free_list);

    for (i=0; i<MAX_FILES; ++i) {
        pthread_rwlock_init(&bypassd_info->bypassd_open_files[i].file_lock, 0);
    }

    bypassd_info->nr_queues = bypassd_create_queues(BYPASSD_NUM_QUEUES);
    if (bypassd_info->nr_queues == 0) {
        bypassd_log("[bypassd_init]: Failed to create user queues\n");
        return -1;
    } else {
        bypassd_log("[bypassd_init]: Created %d queues\n", bypassd_info->nr_queues);
    }

    ret = bypassd_setup_bounce_buffers(BYPASSD_BUF_POOL_SIZE);
    if (ret == 0) {
        bypassd_log("[bypassd_init]: Failed to setup any buffers\n");
        return -1;
    }

    ret = bypassd_setup_prp_buffers(BYPASSD_NUM_PRP_BUFFERS);
    if (ret == 0) {
        bypassd_log("[bypassd_init]: Failed to setup prp buffers\n");
        return -1;
    }

    return 0;
}
