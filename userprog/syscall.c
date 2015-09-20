#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *p = (uint32_t*) f->esp;
  if(p !=NULL && is_user_vaddr(p) && p < (uint32_t*) PHYS_BASE){
    switch((uint32_t) *p)
      {
      case SYS_HALT:
        halt();
	break;
      case SYS_EXIT:
        exit((int) *(p + 1));
	break;
      case SYS_EXEC:
	f->eax = exec((char*) *(p + 1));		
	break;
      case SYS_WAIT:
	f->eax = wait((pid_t) *(p + 1));
	break;
      case SYS_CREATE:
	f->eax = create((char*) *(p + 1), (unsigned) *(p + 1));
	break;
      case SYS_REMOVE:
	f->eax = remove((char*) *(p + 1));
	break;
      case SYS_OPEN:
	f->eax = open((char*) *(p + 1));
	break;
      case SYS_FILESIZE:
	f->eax = filesize((int) *(p + 1));
	break;
      case SYS_READ:
	f->eax = read((int) *(p + 1), (void*) *(p + 1), (unsigned) *(p + 1));
	break;
      case SYS_WRITE:
	f->eax = write((int) *(p + 1), (void*) *(p + 1), (unsigned) *(p + 1));
	break;
      case SYS_SEEK:
	seek((int) *(p + 1), (unsigned) *(p + 1));
	break;
      case SYS_TELL:
	f->eax = tell((int) *(p + 1));
	break;
      case SYS_CLOSE:
	close((int) *(p + 1));
	break;		       
      default:
	break;
      }
  }
  
  thread_exit ();
}

void halt(void) {
}

void exit(int status) {
}

pid_t exec(const char *cmd_line) {
  return -1;
}

int wait(pid_t pid) {
  return -1;
}

bool create(const char *file, unsigned initial_size) {
  return -1;
}

bool remove(const char *file) {
  return -1;
}

int open(const char *file) {
  return -1;
}

int filesize(int fd) {
  return -1;
}

int read(int fd, void *buffer, unsigned size) {
  return -1;
}

int write(int fd, const void *buffer, unsigned size) {
  return -1;
}

void seek(int fd, unsigned position) {
}

unsigned tell(int fd) {
  return -1;
}

void close(int fd) {
}

