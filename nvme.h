#ifndef _NVME_H
#define _NVME_H

#define SQ_DB(q) (q->db + (2 * q->qid) * q->db_stride)
#define CQ_DB(q) (q->db + (1 + 2 * q->qid) * q->db_stride)

/* MMIO read and write */
#define build_mmio_write(name, size, type, reg, barrier) \
static inline void name(type val, volatile void *addr) \
{ asm volatile("mov" size " %0,%1": :reg (val), \
"m" (*(volatile type *)addr) barrier); }

build_mmio_write(writel, "l", unsigned int, "r", :"memory")

#define writel writel

enum nvme_opcode {
    nvme_cmd_flush      = 0x00,
    nvme_cmd_write      = 0x01,
    nvme_cmd_read       = 0x02,
    nvme_cmd_write_uncor    = 0x04,
    nvme_cmd_compare    = 0x05,
    nvme_cmd_write_zeroes   = 0x08,
    nvme_cmd_dsm        = 0x09,
    nvme_cmd_resv_register  = 0x0d,
    nvme_cmd_resv_report    = 0x0e,
    nvme_cmd_resv_acquire   = 0x11,
    nvme_cmd_resv_release   = 0x15,
};

struct nvme_rw_command {
    __u8            opcode;
    __u8            flags;
    __u16           command_id;
    __le32          nsid;
    __u64           rsvd2;
    __le64          metadata;
    __le64          prp1;
    __le64          prp2;
    __le64          slba;
    __le16          length;
    __le16          control;
    __le32          dsmgmt;
    __le32          reftag;
    __le16          apptag;
    __le16          appmask;
};

struct nvme_completion_entry {
    __le32  result;     /* Used by admin commands to return data */
    __u32   rsvd;
    __le16  sq_head;    /* how much of this queue may be reclaimed */
    __le16  sq_id;      /* submission queue that generated this entry */
    __u16   command_id; /* of the command which completed */
    __le16  status;     /* did the command fail, and if so, why? */
};

struct sw_req *nvme_init_request(struct sw_queue *queue);

void nvme_setup_rw_cmd(struct sw_req *req, struct sw_file *fp,
            uint8_t opcode, unsigned long slba, size_t len);

void nvme_setup_prp(struct sw_req *req, unsigned int nr_pages);

void nvme_submit_cmd(struct sw_queue *queue, struct nvme_rw_command *cmd);

void nvme_poll(struct sw_queue *queue, __u16 cmd_id);

void nvme_process_completions(struct sw_queue *queue);

#endif

