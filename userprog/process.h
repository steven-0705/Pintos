#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
unsigned supp_page_table_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool supp_page_table_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#define MAX_ARGS 100

#endif /* userprog/process.h */
