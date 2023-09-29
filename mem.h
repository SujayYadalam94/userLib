#ifndef _MEM_H
#define _MEM_H

#include <stdbool.h>

int sw_setup_bounce_buffers(size_t size);
int sw_setup_prp_buffers(unsigned int num);
void sw_release_bounce_buffers(void);
void sw_release_prp_buffers(void); 

void *sw_get_bounce_buf(size_t buf_size);
void sw_get_buffer(struct sw_req *req, char *user_buf, size_t buf_size, size_t len, bool force);
void sw_put_buffer(struct sw_req *req);

void virt_to_phys(void *addr, __u64 *pa_list, unsigned int nr_pages);

#endif
