#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include <stdio.h>
#include "userprog/pagedir.h"

struct list frame_table;
struct lock frame_lock;
struct lock eviction_lock;

void frame_init(void) {
  list_init(&frame_table);
  lock_init(&frame_lock);
  lock_init(&eviction_lock);
}

void *allocate_frame(enum palloc_flags flags) {
  void *page;
  struct frame *f;

  lock_acquire(&frame_lock);
  page = palloc_get_page(flags);
  lock_release(&frame_lock);

  if(page != NULL) {
    f = calloc(sizeof(struct frame), 1);
    if(f == NULL) {
      PANIC("Failed to allocate memory for frame.");
    }
    
    f->page = page;
    f->owner = thread_current();
    
    lock_acquire(&frame_lock);
    list_push_back(&frame_table, &f->elem);
    lock_release(&frame_lock);
  }
  else {
    page = evict_frame();
    ASSERT(page != NULL);
  }

  return page;
}

void* evict_frame(void) {
  struct frame *choice;
  struct thread *current = thread_current();
  struct thread *old;
  struct supp_page *page;
  size_t swap_index = 0;

  lock_acquire(&eviction_lock);

  choice = choose_frame_to_evict();

  lock_release(&eviction_lock);

  if(choice == NULL) {
    PANIC("No frames could be evicted.");
  }

  old = choice->owner;
  page = get_supp_page(&old->supp_page_table, choice->user_addr);

  if(page == NULL) {
    page = calloc(sizeof(struct supp_page), 1);
    if(page == NULL) {
      PANIC("Failed to allocate memory for supplemental page.");
    }
    page->user_addr = choice->user_addr;
    page->type = SWAP;
    add_supp_page(&old->supp_page_table, page);
  }

  if(pagedir_is_dirty(old->pagedir, page->user_addr) || (page->type != FILE)) {
    pin_frame(choice);
    swap_index = swap_out(page->user_addr);
    unpin_frame(choice);
    page->type = page->type | SWAP;
  }

  page->swap_index = swap_index;
  page->swap_writable = *(choice->pte) & PTE_W;

  choice->owner = current;
  choice->pte = NULL;
  choice->user_addr = NULL;

  lock_acquire(&old->pagedir_lock);
  pagedir_clear_page(old->pagedir, page->user_addr);
  lock_release(&old->pagedir_lock);

  page->has_loaded = false;

  return choice->page;
}

struct frame* choose_frame_to_evict(void) {
  struct frame *choice = NULL;
  struct thread *owner;
  struct list_elem *e;
  
  int i;
  for(i = 0; i < 2; i++) {
    for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
      choice = list_entry(e, struct frame, elem);
      if(choice->pinned) {
	continue;
      }
      owner = choice->owner;
      lock_acquire(&owner->pagedir_lock);
      
      if(!pagedir_is_dirty(owner->pagedir, choice->user_addr) && !pagedir_is_accessed(owner->pagedir, choice->user_addr)) {
	lock_release(&owner->pagedir_lock);
	return choice;
      }
      
      lock_release(&owner->pagedir_lock);
    }

    for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
      choice = list_entry(e, struct frame, elem);
      if(choice->pinned) {
	continue;
      }
      owner = choice->owner;
      lock_acquire(&owner->pagedir_lock);
      
      if(pagedir_is_dirty(owner->pagedir, choice->user_addr) && !pagedir_is_accessed(owner->pagedir, choice->user_addr)) {
	lock_release(&owner->pagedir_lock);

	lock_acquire(&frame_lock);
	list_remove(e);
	list_push_back(&frame_table, e);
	lock_release(&frame_lock);

	return choice;
      }
      
      pagedir_set_accessed(owner->pagedir, choice->user_addr, false);
      lock_release(&owner->pagedir_lock);
    }
  }
  return NULL;
}

void pin_frame(struct frame *f) {
  f->pinned = true;
}

void unpin_frame(struct frame *f) {
  f->pinned = false;
}

void pin_page(void *page) {
  struct frame *f = get_frame(page);
  f->pinned = true;
}

void unpin_page(void *page) {
  struct frame *f = get_frame(page);
  f->pinned = false;
}

void set_user_addr(void *page, uint8_t *user_addr) {
  struct frame *f = get_frame(page);
  if(f != NULL) {
    f->user_addr = user_addr;
  }
}

void set_pte(void *page, uint32_t *pte) {
  struct frame *f = get_frame(page);
  if(f != NULL) {
    f->pte = pte;
  }
}

struct frame* get_frame(void *page) {
  struct frame *f;
  struct list_elem *next, *e = list_begin(&frame_table);

  /* Find the frame with given page */
  lock_acquire(&frame_lock);
  while(e != list_end(&frame_table)) {
    next = list_next(e);
    f = list_entry(e, struct frame, elem);
    if(f->page == page) {
      lock_release(&frame_lock);
      return f;
    }
    e = next;
  }
  lock_release(&frame_lock);

  return NULL;
}

void free_frame(void *page) {
  struct frame *f;
  struct list_elem *next, *e = list_begin(&frame_table);

  /* Need to find the frame in the frame_table and free it */
  lock_acquire(&frame_lock);
  while(e != list_end(&frame_table)) {
    next = list_next(e);
    f = list_entry(e, struct frame, elem);
    if(f->page == page) {
      list_remove(e);
      free(f);
      break;
    }
    e = next;
  }
  lock_release(&frame_lock);

  /* Actually free the page */
  palloc_free_page(page);
}

void free_frames(struct thread *owner) {
  struct frame *f;
  struct list_elem *next, *e = list_begin(&frame_table);

  /* Need to find every frame that belongs to owner and free them */
  lock_acquire(&frame_lock);
  while(e != list_end(&frame_table)) {
    next = list_next(e);
    f = list_entry(e, struct frame, elem);
    if(f->owner == owner) {
      list_remove(e);
      free(f);
    }
    e = next;
  }
  lock_release(&frame_lock);
}

