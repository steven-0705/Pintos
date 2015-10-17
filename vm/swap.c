#include "vm/swap.h"
#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "threads/synch.h"

struct block *swap_block;
struct bitmap *swap_map;
struct lock swap_lock;

void swap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);
  size_t size = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_map = bitmap_create(size);
  if(swap_map == NULL) {
    PANIC("Failed to allocate memory for swap map.");
  }
  lock_init(&swap_lock);
}

void destroy_swap_map(void) {
  bitmap_destroy(swap_map);
}

size_t swap_out(void *page) {
  lock_acquire(&swap_lock);
  size_t index = bitmap_scan_and_flip(swap_map, 0, 1, false);
  if(index == BITMAP_ERROR) {
    PANIC("Swap map is full.");
  }
  
  int i;
  for( i = 0; i < SECTORS_PER_PAGE; i++) {
    block_write(swap_block, (index * SECTORS_PER_PAGE) + i, page + (i * BLOCK_SECTOR_SIZE));
  }
  lock_release(&swap_lock);
  return index;
}

void swap_in(void *page, size_t index) {
  lock_acquire(&swap_lock);
  ASSERT(bitmap_test(swap_map, index));
  bitmap_flip(swap_map, index);
  
  int i;
  for( i = 0; i < SECTORS_PER_PAGE; i++) {
    block_read(swap_block, (index * SECTORS_PER_PAGE) + i, page + (i * BLOCK_SECTOR_SIZE));
  }
  lock_release(&swap_lock);
}
