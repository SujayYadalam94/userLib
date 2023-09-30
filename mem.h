#ifndef _MEM_H
#define _MEM_H

#include <stdbool.h>

int  userlib_setup_bounce_buffers(size_t size);
int  userlib_setup_prp_buffers(unsigned int num);
void userlib_release_bounce_buffers(void);
void userlib_release_prp_buffers(void); 

struct userlib_user_buf* userlib_get_bounce_buf(size_t buf_size);
void  userlib_get_buffer(struct userlib_io_req *req, char *user_buf, size_t buf_size, size_t len, bool force);
void  userlib_put_buffer(struct userlib_io_req *req);

void virt_to_phys(void *addr, __u64 *pa_list, unsigned int nr_pages);

#endif
