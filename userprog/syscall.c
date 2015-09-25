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
#include "devices/shutdown.h"

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
      default:
	break;
      }
  }
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
    bool success = filesys_create(file, initial_size);
    return success;
  }
  NOT_REACHED();
}

bool remove(const char *file) {
  if(check_ptr_access((void*) file)) {
    bool success = filesys_remove(file);
    return success;
  }
  NOT_REACHED();
}

int open(const char *file) {
  if(check_ptr_access((void*) file)) {
  }
  /*
  struct file* sFile = filesys_open(file);
  if(!sFile)*/ /*maybe say file == null if doesn't work*/ /*
  { 
    return -1;
  }
  int fd = add_process_file(sFile);
  return fd; */
  NOT_REACHED();
}
							  
int filesize(int fd UNUSED) {
  return -1;
}

int read(int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED) {
  if(check_ptr_access(buffer)) {
    if(fd == STDIN_FILENO)
      {
	unsigned i;
	//char* input = (char*) buffer;
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
  NOT_REACHED();
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd == STDIN_FILENO) {
    exit(-1);
  }
  if(check_ptr_access(buffer)) {
    if(fd == STDOUT_FILENO)
      {
	putbuf(buffer,size);
	return size;
      }
    else {   
      struct file* file = get_process_file(fd);
      if(!file)
	{
	  return -1;
	}
      int bytes = file_write(file,buffer,size); /*check file.h*/
      return bytes; 
    }
  }
  NOT_REACHED();
}

void seek(int fd UNUSED, unsigned position UNUSED) {
}

unsigned tell(int fd UNUSED) {
  return -1;
}

void close(int fd UNUSED) {
  close_process_file(fd); 
}

