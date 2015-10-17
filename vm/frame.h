#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "lib/kernel/list.h"
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame {
  void *page; /* Page for this frame */
  struct thread *owner; /* Thread that owns this frame */
  uint8_t *user_addr; /* User address for this frame */
  uint32_t *pte; /* Page table entry */
  struct list_elem elem; /* List element for frame list */
  bool pinned;
};

void frame_init(void);
void *allocate_frame(enum palloc_flags flags);
void free_frame(void *page);
void free_frames(struct thread *owner);
void set_user_addr(void *page, uint8_t *user_addr);
void set_pte(void *page, uint32_t *pte);
struct frame* get_frame(void *page);
void* evict_frame(void);
struct frame* choose_frame_to_evict(void);
void pin_frame(struct frame *f);
void unpin_frame(struct frame *f);
void pin_page(void *page);
void unpin_page(void *page);

#endif /* vm/frame.h */
