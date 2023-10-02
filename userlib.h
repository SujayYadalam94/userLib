#ifndef _USERLIB_H
#define _USERLIB_H

#include <assert.h>
#include <errno.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h>

#include "spinlock.h"

// UserLib config options
#define USE_FALLOCATE_FOR_APPENDS
#define QUEUE_PER_THREAD
// TODO: Async writes has not been tested completely
#undef  ASYNC_WRITES

#define BYPASSD_BUF_POOL_SIZE   (8 * 1024 * 1024UL) // Total size of the DMA buffer pool
#define BBUF_SIZE               (128 * 1024UL)      // Size of each DMA buffer
#define BBUF_THRESHOLD          (0)                 // Size threshold for using DMA buffers
#define BYPASSD_NUM_PRP_BUFFERS 16                  // For I/O requests with multiple PRPs
#define FALLOC_SIZE             16                  // Append optimization: preallocate blocks

#define MAX_FILES               1024
#define BYPASSD_NUM_QUEUES      20

#define LOGFILE_NAME            "userlib.log"

//---------------------------------------------------------------------------

#define IOCTL_GET_NS_INFO       _IOR('N', 0x50, struct userlib_ns_info)
#define IOCTL_CREATE_QUEUE_PAIR _IOR('N', 0x51, struct userlib_ioctl_queue_info)
#define IOCTL_DELETE_QUEUE_PAIR _IOW('N', 0x52, int)
#define IOCTL_GET_USER_BUF      _IOWR('N', 0x53, struct userlib_ioctl_buf_info)
#define IOCTL_PUT_USER_BUF      _IOW('N', 0x54, struct userlib_ioctl_buf_info)
#define IOCTL_GET_BUF_ADDR      _IOWR('N', 0x55, struct userlib_ioctl_buf_info)

#define BLK_SIZE 512
#define LB_SIZE  4096
#define BLK_ALIGN(len)      (((len)+((BLK_SIZE)-1))&(~((typeof(len))(BLK_SIZE)-1)))
#define BLK_DOWN_ALIGN(len) ((len)&(~((typeof(len))(BLK_SIZE)-1)))

#ifdef DEBUG
void userlib_log(const char *fmt, ...);
#else
#define userlib_log(fmt, ...)
#endif

enum {
    IO_INIT = 1,
    IO_COMPLETE = 2,
    IO_ERROR = 3,
};

struct userlib_ns_info {
    unsigned int ns_id;
    unsigned int lba_start;
    int          lba_shift;
};

struct userlib_io_req {
    struct userlib_user_buf *prp_buf;
    struct userlib_user_buf *buf;

    struct nvme_rw_command *cmd;

    __u16        cmd_id;
    unsigned int status;
    __u64        prp1, prp2;
};

// Get queue information from kernel module
struct userlib_ioctl_queue_info {
    struct nvme_rw_command        *sq_cmds;
    struct nvme_completion_entry  *cqes;
    __u32                         *db;

    int qid;
    int q_depth;
    int db_stride;
};

struct userlib_queue {
    struct nvme_rw_command                *sq_cmds;
    volatile struct nvme_completion_entry *cqes;
    __u32                                 *db;

    int qid;
    int q_depth;
    int db_stride;

    __u16 sq_tail, cq_head;
    __u8  cq_phase;

    userlib_spinlock_t sq_lock;
    userlib_spinlock_t cq_lock;

    struct userlib_io_req* rqs;
    __u16                  cmd_id;

    int pending_io_writes;
};

struct userlib_file {
    char   filename[256];
    size_t size;

    unsigned long old_fva;
    unsigned long fva;

    int    fd;
    loff_t offset;
    int    flags;
    mode_t mode;
    loff_t append_offset;

    struct userlib_queue   *queue;
    struct userlib_ns_info *ns_info;

    bool opened;
    bool data_modified;
    bool metadata_modified;
    __u8 dummy; // for alignment

    pthread_rwlock_t file_lock;
};

// struct used for IOCTL
struct userlib_ioctl_buf_info {
    void         *vaddr;
    unsigned int nr_pages;
    __u64        *dma_addr_list;
};

// struct used for DMA buffers
struct userlib_user_buf {
    void         *vaddr;
    unsigned int nr_pages;
    __u64       *dma_addr_list; // Stores physical addresses of the DMA buffers

    int user;
    LIST_ENTRY(userlib_user_buf) buf_list;
    LIST_ENTRY(userlib_user_buf) prp_list;
};

// state of userLib
struct userlib_info {
    struct userlib_ns_info ns_info;
    struct userlib_file    userlib_open_files[MAX_FILES];

    int nr_open_files;
    int nr_queues;

    int i_fd; //IOCTL fd

    struct userlib_queue *userlib_queue_list[BYPASSD_NUM_QUEUES];
    LIST_HEAD(buf_list, userlib_user_buf) userlib_buf_list;
    LIST_HEAD(prp_list, userlib_user_buf) userlib_prp_free_list;

    userlib_spinlock_t prp_lock;
    userlib_spinlock_t buf_lock;
};

struct userlib_info *userlib_info;
FILE                *logFile;
extern int          userlib_initialized;

long bypassd_gettid();
int  bypassd_open(char* filename, int flags, mode_t mode, int *result);
int  bypassd_close(int fd, int *result);
int  bypassd_read(struct userlib_file *fp, char* buf, size_t len, loff_t offset, size_t* result);
int  bypassd_write(struct userlib_file *fp, char* buf, size_t len, loff_t offset, size_t* result);
int  bypassd_lseek(struct userlib_file *fp, off_t offset, int whence, off_t* result);
int  bypassd_fallocate(struct userlib_file *fp, int mode, off_t offset, off_t len, int* result);
int  bypassd_ftruncate(struct userlib_file *fp, off_t length, int* result);
void bypassd_fdatasync(struct userlib_file *fp);
void userlib_exit();
int  userlib_init();

#endif
