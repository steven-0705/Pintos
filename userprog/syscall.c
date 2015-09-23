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
struct process_file{
  struct file* file;
  int fd;
  struct list_elem elem;
};

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
	f->eax = create((char*) *(p + 1), (unsigned) *(p + 2));
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
	f->eax = read((int) *(p + 1), (void*) *(p + 2), (unsigned) *(p + 3));
	break;
      case SYS_WRITE:
	f->eax = write((int) *(p + 1), (void*) *(p + 2), (unsigned) *(p + 3));
	break;
      case SYS_SEEK:
	seek((int) *(p + 1), (unsigned) *(p + 2));
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


int add_process_file (struct file* file)
{
  struct process_file* pFile = malloc(sizeof(struct process_file));
  pFile->file = file;
  pFile->fd = thread_current()->fd; 
  thread_current()->fd++;
  list_push_back(&thread_current()->fileList,&pFile->elem); /*list.h*/
  return pFile->fd;
}


struct file* get_process_file(int fd)
{
  struct thread* th = thread_current();
  struct list_elem* elem;

  for(elem = list_begin(&th->fileList); elem!=list_end(&th->fileList);
    elem = list_next (elem))
  {
    struct process_file* pFile = list_entry (elem, struct process_file, elem);
    if(fd == pFile->fd)
    {
      return pFile->file;
    }
  }

  return NULL;
}
/*if fd = -1 then close all the processes*/
void close_process_file(int fd)
{
  struct thread* th = thread_current();
  struct list_elem *next, *e = list_begin(&th->fileList);
  while(e !=list_end(&th->fileList))
  {
    next=list_next(e);
    struct process_file* pf = list_entry(e, struct process_file, elem);
    if(fd == pf->fd || fd == -1)
    {
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      if(fd!=-1)
      {
        return;
      }
    }
    e=next;
  
  }
}


void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
}

pid_t exec(const char *cmd_line) {
  return -1;
}

int wait(pid_t pid) {
  int status = process_wait(pid);
  return status;
}

bool create(const char *file, unsigned initial_size) {
  bool success = filesys_create(file, initial_size);
  return success;
}

bool remove(const char *file) {
  bool success = filesys_remove(file);
  return success;
}

int open(const char *file) {
  struct file* sFile = filesys_open(file);
  if(!sFile) /*maybe say file == null if doesn't work*/
  { 
    return -1;
  }
  int fd = add_process_file(sFile);
  return fd;
}

int filesize(int fd) {
  return -1;
}

int read(int fd, void *buffer, unsigned size) {
  if(fd == 0)
  {
    unsigned i;
    char* input = (char*) buffer;
    for(i=0; i< size; i++)
    {
      /*input[i]=getchar();*/
    }
    return size;
  }
  struct file* file = get_process_file(fd);
  if(!file)
  {
    return -1;
  }
  int bytes = file_read(file, buffer, size); /* check file.h*/
  return bytes;
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd == STDOUT_FILENO)
  {
    putbuf(buffer,size);
    return size;
  }
  struct file* file = get_process_file(fd);
  if(!file)
  {
    return -1;
  }
  int bytes = file_write(file,buffer,size); /*check file.h*/
  return bytes;
}

void seek(int fd, unsigned position) {
}

unsigned tell(int fd) {
  return -1;
}

void close(int fd) {
 close_process_file(fd); 
}

