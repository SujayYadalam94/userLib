#ifndef _SW_LIB_H
#define _SW_LIB_H

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
#undef ASYNC_WRITES

#define SW_BUF_POOL_SIZE (8 * 1024 * 1024UL)

#define BBUF_SIZE  (128 * 1024UL)
#define BBUF_THRESHOLD (0)
#define SW_NUM_PRP_BUFFERS 16
#define FALLOC_SIZE 16

#define MAX_FILES 1024
#define SW_NUM_QUEUES 16

//---------------------------------------------------------------------------

#define IOCTL_GET_NS_INFO       _IOR('N', 0x50, struct sw_ns_info)
#define IOCTL_CREATE_QUEUE_PAIR _IOR('N', 0x51, struct sw_ioctl_queue_info)
#define IOCTL_DELETE_QUEUE_PAIR _IOW('N', 0x52, int)
#define IOCTL_GET_USER_BUF      _IOWR('N', 0x53, struct sw_ioctl_buf_info)
#define IOCTL_PUT_USER_BUF      _IOW('N', 0x54, struct sw_ioctl_buf_info)
#define IOCTL_GET_BUF_ADDR      _IOWR('N', 0x55, struct sw_ioctl_buf_info)


#define BLK_SIZE 512
#define LB_SIZE 4096
#define BLK_ALIGN(len)      (((len)+((BLK_SIZE)-1))&(~((typeof(len))(BLK_SIZE)-1)))
#define BLK_DOWN_ALIGN(len) ((len)&(~((typeof(len))(BLK_SIZE)-1)))

#ifdef DEBUG
void sw_log(const char *fmt, ...);
#else
#define sw_log(fmt, ...)
#endif

enum {
    IO_INIT = 1,
    IO_COMPLETE = 2,
    IO_ERROR = 3,
};

struct sw_ns_info {
    unsigned int ns_id;
    unsigned int lba_start;
    int lba_shift;
};

struct sw_req {
    struct sw_user_buf *prp_buf;
    struct sw_user_buf *buf;

    struct nvme_rw_command *cmd;

    __u16 cmd_id;
    unsigned int status;
    __u64 prp1, prp2;
};

// Get queue information from kernel module
struct sw_ioctl_queue_info {
    struct nvme_rw_command *sq_cmds;
    struct nvme_completion_entry  *cqes;
    __u32 *db;

    int qid;
    int q_depth;
    int db_stride;
};

struct sw_queue {
    struct nvme_rw_command *sq_cmds;
    volatile struct nvme_completion_entry *cqes;
    __u32 *db;

    int qid;
    int q_depth;
    int db_stride;

    __u16 sq_tail, cq_head;
    __u8  cq_phase;

    sw_spinlock_t sq_lock;
    sw_spinlock_t cq_lock;

    struct sw_req* rqs;
    __u16 cmd_id;

    int pending_io_writes;
};

struct sw_file {
    char filename[256];
    size_t size;

    unsigned long old_fva;
    unsigned long fva;

    int fd;
    loff_t offset;
    int flags;
    mode_t mode;
    loff_t append_offset;

    struct sw_queue *queue;
    struct sw_ns_info *ns_info;

    bool opened;
    bool data_modified;
    bool metadata_modified;
    __u8 dummy; // for alignment

    pthread_rwlock_t file_lock;
};

// struct used for IOCTL
struct sw_ioctl_buf_info {
    void *vaddr;
    unsigned int nr_pages;
    __u64 *dma_addr_list;
};

struct sw_user_buf {
    void *vaddr;
    unsigned int nr_pages;
    __u64 *dma_addr_list;

    int user;
    LIST_ENTRY(sw_user_buf) buf_list;
    LIST_ENTRY(sw_user_buf) prp_list;
};

struct sw_info {
    struct sw_ns_info ns_info;
    struct sw_file sw_open_files[MAX_FILES];

    int nr_open_files;
    int nr_queues;

    int i_fd; //IOCTL fd

    struct sw_queue *sw_queue_list[SW_NUM_QUEUES];
    LIST_HEAD(buf_list, sw_user_buf) sw_buf_list;
    LIST_HEAD(prp_list, sw_user_buf) sw_prp_free_list;

    sw_spinlock_t prp_lock;
    sw_spinlock_t buf_lock;
};

struct sw_info *sw_info;
extern int sw_initialized;

char *bounce_buf;
struct sw_user_buf buf_info;
FILE *logFile;

long sw_gettid();
int sw_open(char* filename, int flags, mode_t mode, int *result);
int sw_close(int fd, int *result);
int sw_read(struct sw_file *fp, char* buf, size_t len, loff_t offset, size_t* result);
int sw_write(struct sw_file *fp, char* buf, size_t len, loff_t offset, size_t* result);
int sw_lseek(struct sw_file *fp, off_t offset, int whence, off_t* result);
int sw_fallocate(struct sw_file *fp, int mode, off_t offset, off_t len, int* result);
int sw_ftruncate(struct sw_file *fp, off_t length, int* result);
void sw_fdatasync();
void sw_exit();
int sw_init();

#endif
