#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "devices/timer.h"
#include "threads/synch.h"
#include <list.h>

#define MAX_CACHE_SIZE 64
#define WRITE_BACK_INTERVAL TIMER_FREQ*5

struct list cache;
uint32_t cache_size;
struct lock cache_lock;

struct cache_info {
  uint8_t block[BLOCK_SECTOR_SIZE];
  block_sector_t sector;
  bool is_dirty;
  bool is_accessed;
  int open_cnt;
  struct list_elem elem;
};

void cache_init(void);
struct cache_info *get_cache_block(block_sector_t sector);
struct cache_info *get_or_evict_cache_block(block_sector_t sector, bool dirty_bit);
struct cache_info *evict_cache_block(block_sector_t sector, bool dirty_bit);
void cache_write_to_disk(bool halt);
void cache_write_back(void *aux);
void create_cache_readahead(block_sector_t sector);
void cache_readahead(void *aux);

#endif /* filesys/cache.h */
