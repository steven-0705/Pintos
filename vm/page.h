#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include <stddef.h>
#include "filesys/off_t.h"

enum supp_page_type {
  FILE = 1,
  SWAP = 2,
  FILE_SWAP = 3,
  MMAP = 4,
  HASH_ERROR = 5
};

struct supp_page {
  struct file *file;
  void *user_addr;
  off_t offset;
  uint32_t zero_bytes;
  uint32_t read_bytes;
  bool writable;
  bool has_loaded;
  bool is_mapped;

  size_t swap_index;
  bool swap_writable;

  enum supp_page_type type;

  struct hash_elem elem;
};

struct supp_page* create_supp_page(struct file *file, uint8_t *user_addr, off_t offset, uint32_t zero_bytes, uint32_t read_bytes, bool writable);
bool add_supp_page(struct hash *supp_page_table, struct supp_page *page);
struct supp_page* get_supp_page(struct hash *supp_page_table, uint8_t *user_addr);
void delete_supp_page(struct supp_page *page);
void free_supp_page(struct hash_elem *e, void *aux);
void free_supp_pages(struct hash *supp_page_table);

#endif /* vm/page.h */
