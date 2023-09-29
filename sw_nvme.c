#include <stdatomic.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "help.h"
#include "sw_lib.h"
#include "sw_mem.h"
#include "sw_nvme.h"

extern FILE *logFile;

double avg = 0;
int scount = 0;
__thread struct timespec stime,etime;

struct sw_req *nvme_init_request(struct sw_queue *queue) {
    __u16 cmd_id;
    struct sw_req *req;

    cmd_id = __atomic_fetch_add(&queue->cmd_id, 1, __ATOMIC_SEQ_CST);
    cmd_id = cmd_id % queue->q_depth;

    req = &queue->rqs[cmd_id];
    req->prp_buf = NULL;
    req->buf = NULL;
    req->cmd = calloc(1, sizeof(struct nvme_rw_command));
    req->cmd_id = cmd_id;
    req->status = IO_INIT;

    return req;
}

inline void nvme_setup_rw_cmd(struct sw_req *req, struct sw_file *fp,
            uint8_t opcode, unsigned long slba, size_t len) {
    struct nvme_rw_command *cmd = req->cmd;

    cmd->opcode = opcode;
    cmd->command_id = req->cmd_id;
    cmd->nsid = fp->ns_info->ns_id;
    cmd->prp1 = req->prp1;
    cmd->prp2 = req->prp2;
    cmd->slba = fp->ns_info->lba_start + slba;
    cmd->length = (BLK_ALIGN(len) >> fp->ns_info->lba_shift) - 1;
    cmd->control = 0;
    cmd->dsmgmt = 0;

    return;
}

void nvme_setup_prp(struct sw_req *req, unsigned int nr_pages) {
    struct sw_user_buf *prp_buf;
    __u64 *pa_list;
    __u64 *prp_vaddr;
    unsigned int i;

    pa_list = req->buf->dma_addr_list;
    req->prp1 = pa_list[0];

    if (nr_pages == 1) {
        req->prp2 = 0;
    } else if (nr_pages == 2) {
        req->prp2 = pa_list[1];
    } else if (nr_pages > 2) {
        sw_spinlock_lock(&sw_info->prp_lock);
        prp_buf = LIST_FIRST(&sw_info->sw_prp_free_list);
        if (!prp_buf) {
            assert(0);
        }
        LIST_REMOVE(prp_buf, prp_list);
        sw_spinlock_unlock(&sw_info->prp_lock);

        req->prp_buf = prp_buf;

        prp_vaddr = (__u64 *)prp_buf->vaddr;
        req->prp2 = prp_buf->dma_addr_list[0];
        for (i=1; i<nr_pages; ++i) {
            prp_vaddr[i-1] = pa_list[i];
        }
    }
}

void nvme_submit_cmd(struct sw_queue *queue, struct nvme_rw_command *cmd) {
#ifdef DEBUG
    clock_gettime(CLOCK_REALTIME, &stime);
#endif
    sw_spinlock_lock(&queue->sq_lock);
    memcpy(&queue->sq_cmds[queue->sq_tail], cmd, sizeof(*cmd));
    if (++queue->sq_tail == queue->q_depth)
        queue->sq_tail = 0;
    writel(queue->sq_tail, SQ_DB(queue));
    sw_spinlock_unlock(&queue->sq_lock);

    if (cmd->opcode == nvme_cmd_write) {
        atomic_fetch_add(&queue->pending_io_writes, 1);
    }
}

void complete_io(struct sw_req *req) {
    if (req->prp_buf) {
        memset(req->prp_buf->vaddr, 0, PAGE_SIZE);
        sw_spinlock_lock(&sw_info->prp_lock);
        LIST_INSERT_HEAD(&sw_info->sw_prp_free_list, req->prp_buf, prp_list);
        sw_spinlock_unlock(&sw_info->prp_lock); 
    }

    // Free buffer only for writes
    // For reads, free after memcpy(). This is done in sw_read().
    if (req->cmd->opcode == nvme_cmd_write) {
        sw_put_buffer(req);
    }

    req->status = IO_COMPLETE;
    free(req->cmd);
}

static inline bool nvme_cqe_pending(struct sw_queue *queue) {
    return (queue->cqes[queue->cq_head].status & 1) == queue->cq_phase;
}

static inline void nvme_update_cq_head(struct sw_queue *queue) {
        queue->cq_head++;
        if (queue->cq_head == queue->q_depth) {
            queue->cq_head = 0;
            queue->cq_phase = !queue->cq_phase;
        }
}

// Returns when command with cmd_id is complete
// If finds other entries, processes completions for other requests
void nvme_poll(struct sw_queue *queue, __u16 cmd_id) {
    volatile struct sw_req *req;
    volatile struct nvme_completion_entry *cqe;
    __u16 start = 0, end = 0;

    req = &queue->rqs[cmd_id];
    for(;;) {
        if (req->status == IO_COMPLETE) {
            break;
        }

        if (!nvme_cqe_pending(queue))
            continue;

        if (sw_spinlock_trylock(&queue->cq_lock) == 1) {
            start = queue->cq_head;
            while (nvme_cqe_pending(queue)) {
                nvme_update_cq_head(queue);
            }
            end = queue->cq_head;
            // Ring doorbell
            if (start != end)
                writel(queue->cq_head, CQ_DB(queue));

            sw_spinlock_unlock(&queue->cq_lock);

            while (start != end) {
                cqe = &queue->cqes[start];
                complete_io(&queue->rqs[cqe->command_id]);
                if (++start == queue->q_depth) start = 0;

                if (queue->rqs[cqe->command_id].cmd->opcode == nvme_cmd_write) {
                    atomic_fetch_sub(&queue->pending_io_writes, 1);
                }
            }
            start = end = 0;
        }
    }

#ifdef DEBUG
    clock_gettime(CLOCK_REALTIME, &etime);
    avg += (etime.tv_sec - stime.tv_sec) * 1e6 + (etime.tv_nsec - stime.tv_nsec) / 1e3;
    scount++;
#endif
    return;
}

void nvme_process_completions(struct sw_queue *queue) {
    volatile struct nvme_completion_entry *cqe;
    __u16 start = 0, end = 0;

    if (sw_spinlock_trylock(&queue->cq_lock) == 1) {
        start = queue->cq_head;
        while (nvme_cqe_pending(queue)) {
            nvme_update_cq_head(queue);
        }
        end = queue->cq_head;
        // Ring doorbell
        if (start != end)
            writel(queue->cq_head, CQ_DB(queue));

        sw_spinlock_unlock(&queue->cq_lock);

        while (start != end) {
            cqe = &queue->cqes[start];
            complete_io(&queue->rqs[cqe->command_id]);
            if (++start == queue->q_depth) {
                start = 0;
            }

            if (queue->rqs[cqe->command_id].cmd->opcode == nvme_cmd_write) {
                atomic_fetch_sub(&queue->pending_io_writes, 1);
            }
        }
    }
}
