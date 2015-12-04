#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/list.h"

typedef int pid_t;

struct process_file {
  struct file *file;
  struct dir *dir;
  int fd;
  bool is_dir;
  struct list_elem elem;
};

void syscall_init (void);
bool check_ptr_access(const void *ptr);
int add_process_file (struct file* file);
int add_process_dir(struct dir *dir);
struct process_file* get_process_file(int fd);
void close_process_file(int fd);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
bool chdir (const char* dir);
bool mkdir(const char* dir);
bool readdir(int fd, char* name);
bool isdir(int fd);
int inumber(int fd);

#endif /* userprog/syscall.h */
