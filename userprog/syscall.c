#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "devices/block.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool check_ptr_access(const void *ptr) {
  struct thread *current = thread_current();
  if(ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(current->pagedir, ptr) == NULL) {
    exit(-1);
    return false;
  }
  return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  ASSERT(f != NULL);
  ASSERT(f->esp != NULL);

  uint32_t *p = (uint32_t*) f->esp;
  if(check_ptr_access(p)){
    int syscall_number = (int) *p;
    switch(syscall_number)
      {
      case SYS_HALT:
        halt();
	break;
      case SYS_EXIT:
	if(check_ptr_access(p + 1)) {
	  exit((int) *(p + 1));
	}
	break;
      case SYS_EXEC:
	if(check_ptr_access(p + 1)) {
	  f->eax = exec((char*) *(p + 1));
	}		
	break;
      case SYS_WAIT:
	if(check_ptr_access(p + 1)) {
	  f->eax = wait((pid_t) *(p + 1));
	}
	break;
      case SYS_CREATE:
	if(check_ptr_access(p + 1) && check_ptr_access(p + 2)) {
	  f->eax = create((char*) *(p + 1), (unsigned) *(p + 2));
	}
	break;
      case SYS_REMOVE:
	if(check_ptr_access(p + 1)) {
	  f->eax = remove((char*) *(p + 1));
	}
	break;
      case SYS_OPEN:
	if(check_ptr_access(p + 1)) {
	  f->eax = open((char*) *(p + 1));
	}
	break;
      case SYS_FILESIZE:
	if(check_ptr_access(p + 1)) {
	  f->eax = filesize((int) *(p + 1));
	}
	break;
      case SYS_READ:
	if(check_ptr_access(p + 1) && check_ptr_access(p + 2) && check_ptr_access(p + 3)) {
	  f->eax = read((int) *(p + 1), (void*) *(p + 2), (unsigned) *(p + 3));
	}
	break;
      case SYS_WRITE:
	if(check_ptr_access(p + 1) && check_ptr_access(p + 2) && check_ptr_access(p + 3)) {
	  f->eax = write((int) *(p + 1), (void*) *(p + 2), (unsigned) *(p + 3));
	}
	break;
      case SYS_SEEK:
	if(check_ptr_access(p + 1) && check_ptr_access(p + 2)) {
	  seek((int) *(p + 1), (unsigned) *(p + 2));
	}
	break;
      case SYS_TELL:
	if(check_ptr_access(p + 1)) {
	  f->eax = tell((int) *(p + 1));
	}
	break;
      case SYS_CLOSE:
	if(check_ptr_access(p + 1)) {
	  close((int) *(p + 1));
	}
	break;
      case SYS_CHDIR:
	if(check_ptr_access(p + 1)) {
	  f->eax = chdir((const char *) *(p + 1));
	}
	break;
      case SYS_MKDIR:
	if(check_ptr_access(p + 1)) {
	  f->eax = mkdir((const char *) *(p + 1));
	}
	break;     
      case SYS_READDIR:
	if(check_ptr_access(p + 1) && check_ptr_access(p + 2)) {
	  f->eax = readdir((int) *(p + 1), (char *) *(p + 2));
	}
	break;     
      case SYS_ISDIR:
	if(check_ptr_access(p + 1)) {
	  f->eax = isdir((int) *(p + 1));
	}
	break;     
      case SYS_INUMBER:
	if(check_ptr_access(p + 1)) {
	  f->eax = inumber((int) *(p + 1));
	}
	break;           
      default:
	break;
      }
  }
}

int add_process_file (struct file* file)
{
  struct process_file* pFile = calloc(sizeof(struct process_file), 1);
  pFile->file = file;
  pFile->is_dir = false;
  pFile->fd = thread_current()->fd; 
  thread_current()->fd++;
  list_push_back(&thread_current()->fileList,&pFile->elem); /*list.h*/
  return pFile->fd;
}

int add_process_dir(struct dir *dir) {
  struct process_file *pFile = calloc(sizeof(struct process_file), 1);
  pFile->dir = dir;
  pFile->is_dir = true;
  pFile->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->fileList, &pFile->elem);
  return pFile->fd;
}

struct process_file* get_process_file(int fd)
{
  struct thread* th = thread_current();
  struct list_elem* elem;

  elem = list_tail(&th->fileList);
  while((elem = list_prev(elem)) != list_head(&th->fileList))
  {
    struct process_file* pFile = list_entry (elem, struct process_file, elem);

    if(fd == pFile->fd)
    {
      return pFile;
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
    struct process_file* pFile = list_entry(e, struct process_file, elem);
    if(fd == pFile->fd || fd == -1)
    {
      if(pFile->is_dir) {
	dir_close(pFile->dir);
      }
      else {
	file_close(pFile->file);
      }
      list_remove(&pFile->elem);
      free(pFile);
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
  struct thread *current = thread_current();
  struct thread *parent = current->parent;
  struct child_data *child = get_child(parent, current->tid);

  printf("%s: exit(%d)\n", current->name, status);

  if(child != NULL) {
    lock_acquire(&parent->child_lock);
    child->has_exited = true;
    child->status = status;
    lock_release(&parent->child_lock);
  }

  struct list_elem *e, *next;
  e = list_begin(&current->fileList);

  while(e !=list_end(&current->fileList))
  {
    next=list_next(e);
    struct process_file* pf = list_entry(e, struct process_file, elem);
    close(pf->fd);
    e = next;
  }

  thread_exit();
}

pid_t exec(const char *cmd_line) {
  if(check_ptr_access((void*) cmd_line)) {
    struct thread *current = thread_current();
    tid_t child_tid;

    child_tid = process_execute(cmd_line);
    current->most_recent_child_status = LOADING;

    lock_acquire(&current->child_lock);
    while(current->most_recent_child_status == LOADING) {
      cond_wait(&current->child_wait, &current->child_lock);
    }
    lock_release(&current->child_lock);

    if(current->most_recent_child_status == LOAD_SUCCEEDED) {
      return child_tid;
    }
    else {
      return -1;
    }
  }
  NOT_REACHED();
}

int wait(pid_t pid) {
  int status = process_wait(pid);
  return status;
}

bool create(const char *file, unsigned initial_size) {
  if(check_ptr_access((void*) file)) {
    return filesys_create(file, initial_size, false);
  }
  NOT_REACHED();
}

bool remove(const char *file) {
  if(check_ptr_access((void*) file)) {
    return filesys_remove(file);
  }
  NOT_REACHED();
}

int open(const char *file) {
  if(check_ptr_access((void*) file)) {
    struct file* sFile = filesys_open(file);
    if(!sFile) /*maybe say file == null if doesn't work*/ 
      { 
	return -1;
      }
    int fd;
    if(inode_is_dir(file_get_inode(sFile))) {
      fd = add_process_dir((struct dir *) sFile);
    }
    else {
      fd = add_process_file(sFile);
    }
    return fd; 
  }
  NOT_REACHED();
}
							  
int filesize(int fd) {
  struct process_file *pFile = get_process_file(fd);
  if(!pFile) {
    return -1;
  }
  if(pFile->is_dir) {
    return -1;
  }
  int size = file_length(pFile->file);
  return size;
}

int read(int fd, void *buffer, unsigned size) {
  if(check_ptr_access(buffer)) {
    if((buffer + size) < PHYS_BASE) {
      if(fd == STDIN_FILENO)
	{
	  unsigned i;
	  uint8_t *input = (uint8_t*) buffer;
	  for(i=0; i< size; i++)
	    { 
	      input[i]=input_getc();
	    }
	  return size;
	}
      struct process_file* pFile = get_process_file(fd);
      if(!pFile)
	{
	  return -1;
	}
      if(pFile->is_dir) {
	return -1;
      }
      int bytes = file_read(pFile->file, buffer, size); /* check file.h*/
      return bytes;
    }
  }
  NOT_REACHED();
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd == STDIN_FILENO) {
    exit(-1);
  }
  if(check_ptr_access(buffer)) {
    if((buffer + size) < PHYS_BASE) {
      if(fd == STDOUT_FILENO)
	{
	  putbuf(buffer,size);
	  return size;
	}
      else {   
	struct process_file* pFile = get_process_file(fd);
	if(!pFile)
	  {
	    return -1;
	  }
	if(pFile->is_dir) {
	  return -1;
	}
	int bytes = file_write(pFile->file, buffer, size); /*check file.h*/
	return bytes; 
      }
    }
  }
  NOT_REACHED();
}

void seek(int fd, unsigned position) {
  struct process_file *pFile = get_process_file(fd);
  if(!pFile) {
    return;
  }
  if(pFile->is_dir) {
    return;
  }
  file_seek(pFile->file, position);
}

unsigned tell(int fd) {
  struct process_file *pFile = get_process_file(fd);
  if(!pFile) {
    return -1;
  }
  if(pFile->is_dir) {
    return -1;
  }
  int offset = file_tell(pFile->file);
  return offset;
}

void close(int fd) {
  close_process_file(fd);
}

bool chdir (const char* dir UNUSED)
{
  return filesys_chdir(dir);
}

bool mkdir(const char* dir)
{
  return filesys_create(dir, 0, true);
}

bool readdir(int fd, char* name)
{
  struct process_file *pFile = get_process_file(fd);
  if(!pFile)
  {
    return false;
  }
  if(!pFile->is_dir)
  {
    return false;
  }
  if(!dir_readdir(pFile->dir, name))
  {
    return false;
  }
  return true;
}

bool isdir(int fd)
{
  struct process_file *pFile = get_process_file(fd);
  if(!pFile)
  {
    return -1;
  }
  return pFile->is_dir;
}

int inumber(int fd)
{
  struct process_file *pFile = get_process_file(fd);
  if(!pFile)
  {
    return -1;
  }
  block_sector_t inumber;
  if(pFile->is_dir)
  {
    inumber = inode_get_inumber(dir_get_inode(pFile->dir));
  }
  else
  {
    inumber = inode_get_inumber(file_get_inode(pFile->file));
  }
  return inumber;
}

