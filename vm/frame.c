#include "vm/frame.h"
#include "threads/malloc.h"
#include <stdio.h>

struct list frame_table;
struct lock frame_lock;

void frame_init(void) {
  list_init(&frame_table);
  lock_init(&frame_lock);
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
    /* Need to do eviction stuff here */
    PANIC("Out of frames.");
  }

  return page;
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

