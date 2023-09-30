#include "pa_maps.h"
#include "userlib.h"
#include "mem.h"

extern FILE *logFile;

/*****************************************************************************/

int userlib_setup_bounce_buffers(size_t mem_pool_size) {
    struct userlib_ioctl_buf_info buf_info;
    struct userlib_user_buf       *ubuf;
    int                           ret;
    unsigned int                  i = 0;

    mem_pool_size = LARGE_PAGE_ALIGN(mem_pool_size);

    buf_info.vaddr         = mmap(NULL, mem_pool_size, PROT_READ | PROT_WRITE, \
                                MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0);
    buf_info.nr_pages      = mem_pool_size/PAGE_SIZE;
    buf_info.dma_addr_list = malloc(sizeof(__u64) * buf_info.nr_pages);
    ret = ioctl(userlib_info->i_fd, IOCTL_GET_USER_BUF, &buf_info);
    if (ret != 0) {
        userlib_log("[%s]: Error allocating buffer\n", __func__);
        return 0;
    } else if (buf_info.nr_pages != mem_pool_size/PAGE_SIZE) {
        userlib_log("[%s]: Allocated partial memory\n", __func__);
    }

    while ((i * BBUF_SIZE) < mem_pool_size) {
        ubuf                = malloc(sizeof(*ubuf));
        ubuf->vaddr         = buf_info.vaddr + (i * BBUF_SIZE);
        ubuf->nr_pages      = BBUF_SIZE/PAGE_SIZE;
        ubuf->dma_addr_list = malloc(sizeof(__u64) * ubuf->nr_pages);
        memcpy(ubuf->dma_addr_list, buf_info.dma_addr_list + i * ubuf->nr_pages,
                    sizeof(__u64) * ubuf->nr_pages);
        ubuf->user = 0;
        LIST_INSERT_HEAD(&userlib_info->userlib_buf_list, ubuf, buf_list);

        i++;
    }

    free(buf_info.dma_addr_list);

    userlib_log("[%s]: allocated %d buffers of size %ld\n", __func__, i, BBUF_SIZE);
   
    return mem_pool_size;
}

int userlib_setup_prp_buffers(unsigned int num) {
    struct userlib_ioctl_buf_info buf_info;
    struct userlib_user_buf       *prp_buf;
    unsigned int                  i;
    int                           ret;

    buf_info.dma_addr_list = malloc(sizeof(__u64));

    for (i=0; i<num; ++i) {
        buf_info.vaddr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        buf_info.nr_pages = 1;
        ret = ioctl(userlib_info->i_fd, IOCTL_GET_USER_BUF, &buf_info);
        if (ret != 0) {
            userlib_log("[%s]: Error allocating buffer\n", __func__);
            break;
        }

        prp_buf                = calloc(1, sizeof(*prp_buf));
        prp_buf->vaddr         = buf_info.vaddr;
        prp_buf->nr_pages      = 1;
        prp_buf->dma_addr_list = malloc(sizeof(__u64));
        memcpy(prp_buf->dma_addr_list, buf_info.dma_addr_list, sizeof(__u64));

        LIST_INSERT_HEAD(&userlib_info->userlib_prp_free_list, prp_buf, prp_list);
    }

    free(buf_info.dma_addr_list);
    return i;
}

// TODO: Can we make this faster?
struct userlib_user_buf *userlib_get_bounce_buf(size_t buf_size) {
    struct userlib_user_buf *ubuf;

    // TODO: implement merging buffers for larger sizes
    if (buf_size > BBUF_SIZE) {
        userlib_log("[%s]: requested size %ld larger than available\n", __func__, buf_size);
        return NULL;
    }

    userlib_spinlock_lock(&userlib_info->buf_lock);
    ubuf = LIST_FIRST(&userlib_info->userlib_buf_list);
    if (!ubuf) {
        userlib_log("[%s]: No free buffers\n", __func__);
        userlib_spinlock_unlock(&userlib_info->buf_lock);
        return NULL;
    }
    LIST_REMOVE(ubuf, buf_list);
    userlib_spinlock_unlock(&userlib_info->buf_lock);

    return ubuf;
}

void userlib_get_buffer(struct userlib_io_req *req, char* user_buf, size_t io_size, size_t len, bool force) {
    struct userlib_user_buf       *ubuf;
    struct userlib_ioctl_buf_info ubuf_info;

    // If user requested IO is unaligned, we need to use bounce buffer.
    // Else read DMA would overwrite user buf beyond len.
    if ((len % BLK_SIZE != 0) || force) {
        goto get_bounce_buf;
    }

    if (((io_size >= BBUF_THRESHOLD) && ((uintptr_t)user_buf % BLK_SIZE == 0))) {
        size_t start = (uintptr_t)user_buf & (PAGE_SIZE-1);
        size_t temp  = io_size + start;
        unsigned int nr_pages = DIV_ROUND_UP(temp, PAGE_SIZE);

        if(nr_pages > PAGE_ALIGN(io_size)/PAGE_SIZE) {
            goto get_bounce_buf;
        }

        ubuf_info.vaddr         = user_buf;
        ubuf_info.nr_pages      = nr_pages;
        ubuf_info.dma_addr_list = malloc(sizeof(__u64) * nr_pages);

        int ret = ioctl(userlib_info->i_fd, IOCTL_GET_BUF_ADDR, &ubuf_info);
        if (ret != 0) {
            userlib_log("[%s]: Get buf addr ioctl failed\n", __func__);

            ubuf_info.vaddr    = user_buf;
            ubuf_info.nr_pages = nr_pages;
            ret = ioctl(userlib_info->i_fd, IOCTL_GET_USER_BUF, &ubuf_info);
            if (ret != 0) {
                userlib_log("[%s]: Get user buf ioctl also failed\n", __func__);
                free(ubuf_info.dma_addr_list);
            }
        }

        ubuf = malloc(sizeof(struct userlib_user_buf));
        ubuf->vaddr             = user_buf;
        ubuf->nr_pages          = ubuf_info.nr_pages;
        ubuf->dma_addr_list     = ubuf_info.dma_addr_list;
        ubuf->dma_addr_list[0] += start;
        ubuf->user              = 1;

        req->buf = ubuf;
    }

get_bounce_buf:
    if (!req->buf) {
        req->buf = userlib_get_bounce_buf(PAGE_ALIGN(io_size));
    }
}

void userlib_put_buffer(struct userlib_io_req *req)
{
    struct userlib_user_buf *buf = req->buf;

    if (!req) {
        userlib_log("[%s]: Invalid argument\n", __func__);
        return;
    }

    if (buf->user == 1) {
        free(req->buf->dma_addr_list);
        free(req->buf);
    } else {
        userlib_spinlock_lock(&userlib_info->buf_lock);
        LIST_INSERT_HEAD(&userlib_info->userlib_buf_list, req->buf, buf_list);
        userlib_spinlock_unlock(&userlib_info->buf_lock);
    }
}

void userlib_release_bounce_buffers(void) {
    struct userlib_user_buf       *ubuf, *next;
    struct userlib_ioctl_buf_info buf_info;

    ubuf = LIST_FIRST(&userlib_info->userlib_buf_list);
    while (ubuf != NULL) {
        next = LIST_NEXT(ubuf, buf_list);

        buf_info.vaddr         = ubuf->vaddr;
        buf_info.nr_pages      = ubuf->nr_pages;
        buf_info.dma_addr_list = ubuf->dma_addr_list;
        ioctl(userlib_info->i_fd, IOCTL_PUT_USER_BUF, &buf_info);

        munmap(ubuf->vaddr, (ubuf->nr_pages*PAGE_SIZE)); //TODO: mmap size could be different
        free(ubuf->dma_addr_list);
        LIST_REMOVE(ubuf, buf_list);
        free(ubuf);

        ubuf = next;
    }

    return;
}

void userlib_release_prp_buffers(void) {
    struct userlib_user_buf       *prp_buf, *next;
    struct userlib_ioctl_buf_info buf_info;

    buf_info.dma_addr_list = malloc(sizeof(__u64));

    prp_buf = LIST_FIRST(&userlib_info->userlib_prp_free_list);
    while (prp_buf != NULL) {
        next = LIST_NEXT(prp_buf, prp_list);

        buf_info.vaddr    = prp_buf->vaddr;
        buf_info.nr_pages = prp_buf->nr_pages;
        memcpy(buf_info.dma_addr_list, prp_buf->dma_addr_list,
                    sizeof(__u64));
        ioctl(userlib_info->i_fd, IOCTL_PUT_USER_BUF, &buf_info);

        munmap(prp_buf->vaddr, PAGE_SIZE);
        free(prp_buf->dma_addr_list);
        LIST_REMOVE(prp_buf, prp_list);
        free(prp_buf);

        prp_buf = next;
    }

    free(buf_info.dma_addr_list);
}
