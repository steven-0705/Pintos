#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_file{
  struct file* file;
  int fd;
  struct list_elem elem;
};

bool check_ptr_access(void *ptr);

int add_process_file (struct file* file);
struct file* get_process_file(int fd);
void close_process_file(int fd);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#define MAX_ARGS 100

#endif /* userprog/process.h */
