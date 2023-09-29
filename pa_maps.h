#ifndef _PA_MAPS_H
#define _PA_MAPS_H

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define _ALIGN(len, size)   (typeof(len))(((len)+((size)-1))&(~((typeof(len))(size)-1)))
#define PAGE_ALIGN(len) _ALIGN(len, PAGE_SIZE)

#define LARGE_PAGE_SHIFT 21
#define LARGE_PAGE_SIZE  (1UL << PAGE_SHIFT)
#define LARGE_PAGE_ALIGN(len) _ALIGN(len, LARGE_PAGE_SIZE)

#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((unsigned long long)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define PHYSICAL_PAGE_MASK 	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK		((unsigned long)PHYSICAL_PAGE_MASK)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
/******************************************************************************
 * Helper Functions
 */

/*
 * Print the given message and exit with a failed status.
 */
#define die(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

/*
 * Retrieve the system's page size.
 */
long get_page_size(void);

/*
 * A function that prints the process's virtual memory map.
 * It prints the populated virtual memory areas of the process, their
 * permissions, and the name of the file they map, if any.
 *
 * For further details, see `/proc/[pid]/maps` in proc(5) (or online at:
 * https://man7.org/linux/man-pages/man5/proc.5.html).
 */
void show_maps(void);

/*
 * Search maps for a specific VA.
 * If populated, print to stdout the virtual address area (VMA) it belongs to,
 * along with its permissions, etc.
 */
void show_va_info(uint64_t va);

/*
 * A function that receives a virtual address (VA) as an argument and, if it is
 * mapped, it returns the physical address (PA) that it maps to.
 * If the VA is not mapped, it returns 0.
 *
 * For further details, see `/proc/[pid]/pagemap` in proc(5) (or online at:
 * https://man7.org/linux/man-pages/man5/proc.5.html), as well as the Linux
 * documentation at: https://www.kernel.org/doc/Documentation/vm/pagemap.txt.
 */
uint64_t get_physical_frame(unsigned long virt_addr);
uint64_t get_physical_frame_fast(unsigned long *virt_addr, unsigned long lblk);

void press_enter(void);

#endif /* MAP_H */

