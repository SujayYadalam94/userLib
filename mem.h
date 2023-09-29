#ifndef _MEM_H
#define _MEM_H

#include <stdbool.h>

int bypassd_setup_bounce_buffers(size_t size);
int bypassd_setup_prp_buffers(unsigned int num);
void bypassd_release_bounce_buffers(void);
void bypassd_release_prp_buffers(void); 

void *bypassd_get_bounce_buf(size_t buf_size);
void bypassd_get_buffer(struct bypassd_req *req, char *user_buf, size_t buf_size, size_t len, bool force);
void bypassd_put_buffer(struct bypassd_req *req);

void virt_to_phys(void *addr, __u64 *pa_list, unsigned int nr_pages);

#endif
