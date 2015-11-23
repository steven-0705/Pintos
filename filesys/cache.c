#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"

void cache_init(void) {
  list_init(&cache);
  cache_size = 0;
  lock_init(&cache_lock);
  thread_create("cache_writeback", 0, cache_write_back, NULL);
}

struct cache_info *get_cache_block(block_sector_t sector, bool dirty_bit) {
  struct cache_info *info;
  struct list_elem *e;

  lock_acquire(&cache_lock);
  for(e = list_begin(&cache); e != list_end(&cache); e = list_next(e)) {
    info = list_entry(e, struct cache_info, elem);
    if(info->sector == sector) {
      info->is_dirty |= dirty_bit;
      info->is_accessed = true;
      info->readable = true;
      lock_release(&cache_lock);
      return info;
    }
  }
  info = evict_cache_block(sector, dirty_bit);
  if(!info) {
    PANIC("Failed to allocate memory for the cache");
  }
  lock_release(&cache_lock);
  return info;
}

struct cache_info *evict_cache_block(block_sector_t sector, bool dirty_bit) {
  struct cache_info *info;
  struct list_elem *e;
  bool done = false;

  if(cache_size < MAX_CACHE_SIZE) {
    cache_size++;
    info = calloc(sizeof(struct cache_info), 1);
    if(!info) {
      PANIC("Failed to allocate memory for cache info");
    }
    list_push_back(&cache, &info->elem);
  }
  else {
    while(!done) {
      for(e = list_begin(&cache); e != list_end(&cache); e = list_next(e)) {
	info = list_entry(e, struct cache_info, elem);
	if(info->readable) {
	  continue;
	}
	if(!info->is_accessed) {
	  if(info->is_dirty) {
	    block_write(fs_device, info->sector, &info->block);
	  }
	  done = true;
	  break;
	}
	else {
	  info->is_accessed = false;
	}
      }
    }
  }
  info->sector = sector;
  info->readable = true;
  block_read(fs_device, info->sector, &info->block);
  info->is_dirty = dirty_bit;
  info->is_accessed = true;
  return info;
}

void cache_write_to_disk(bool halt) {
  struct cache_info *info;
  struct list_elem *e, *next;

  lock_acquire(&cache_lock);
  for(e = list_begin(&cache); e != list_end(&cache); e = next) {
    next = list_next(e);
    info = list_entry(e, struct cache_info, elem);
    if(info->is_dirty) {
      block_write(fs_device, info->sector, &info->block);
      info->is_dirty = false;
    }
    if(halt) {
      list_remove(&info->elem);
      free(info);
    }
  }
  lock_release(&cache_lock);
}

void cache_write_back(void *aux UNUSED) {
  while(true) {
    timer_sleep(WRITE_BACK_INTERVAL);
    cache_write_to_disk(false);
  }
}
