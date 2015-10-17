#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);
void destroy_swap_map(void);
size_t swap_out(void *page);
void swap_in(void *page, size_t index);

#endif /* vm/swap.h */
