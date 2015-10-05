#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"

struct supp_page* create_supp_page(struct file *file, uint8_t *user_addr, off_t offset, uint32_t zero_bytes, uint32_t read_bytes, bool writable) {
  struct supp_page *page = calloc(sizeof(struct supp_page), 1);
  if(page == NULL) {
    PANIC("Failed to allocate memory for supplemental page.");
  }

  page->file = file;
  page->user_addr = (void*) user_addr;
  page->offset = offset;
  page->zero_bytes = zero_bytes;
  page->read_bytes = read_bytes;
  page->writable = writable;
  page->has_loaded = false;

  return page;
}

bool add_supp_page(struct hash *supp_page_table, struct supp_page *page) {
  struct hash_elem *elem = hash_insert(supp_page_table, &page->elem);
  if(elem == NULL) {
    return true;
  }
  return false;
}

struct supp_page* get_supp_page(struct hash *supp_page_table, uint8_t *user_addr) {
  struct supp_page page;
  struct hash_elem *e;

  page.user_addr = user_addr;
  e = hash_find(supp_page_table, &page.elem);
  if(e == NULL) {
    return NULL;
  }
  return hash_entry(e, struct supp_page, elem);
}

void delete_supp_page(struct supp_page *page) {
  struct thread *current = thread_current();
  hash_delete(&current->supp_page_table, &page->elem);
}

void free_supp_page(struct hash_elem *e, void *aux UNUSED) {
  struct supp_page *page = hash_entry(e, struct supp_page, elem);
  free(page);
}

void free_supp_pages(struct hash *supp_page_table) {
  hash_destroy(supp_page_table, free_supp_page);
}
