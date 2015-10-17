#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/list.h"

typedef int pid_t;

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct mmap_file{
	struct supp_page *spte;
	int mapid;
	struct list_elem elem;
};

void syscall_init (void);
bool check_ptr_access(const void *ptr);
int add_process_file (struct file* file);
struct file* get_process_file(int fd);
void close_process_file(int fd);
void lock_filesys(void);
void release_filesys(void);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size, uint32_t *stack_ptr);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int mmap(int fd, void* addr);
void munmap(int mapping);
void remove_process_mmap(int mapping);
bool add_mmap_to_page_table(struct file* file, int32_t offset, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes);
bool add_process_mmap(struct supp_page* spte);

#endif /* userprog/syscall.h */
