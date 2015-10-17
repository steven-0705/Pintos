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
#include "userprog/exception.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
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
syscall_handler (struct intr_frame *f) 
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
	  f->eax = read((int) *(p + 1), (void*) *(p + 2), (unsigned) *(p + 3), p);
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

void lock_filesys(void) {
  if(!lock_held_by_current_thread(&filesys_lock)) {
    lock_acquire(&filesys_lock);
  }
}

void release_filesys(void) {
  if(lock_held_by_current_thread(&filesys_lock)) {
    lock_release(&filesys_lock);
  }
}

int add_process_file (struct file* file)
{
  struct process_file* pFile = calloc(sizeof(struct process_file), 1);
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

  elem = list_tail(&th->fileList);
  while((elem = list_prev(elem)) != list_head(&th->fileList))
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
    lock_filesys();
    bool success = filesys_create(file, initial_size);
    release_filesys();
    return success;
  }
  NOT_REACHED();
}

bool remove(const char *file) {
  if(check_ptr_access((void*) file)) {
    lock_filesys();
    bool success = filesys_remove(file);
    release_filesys();
    return success;
  }
  NOT_REACHED();
}

int open(const char *file) {
  if(check_ptr_access((void*) file)) {
    lock_filesys();
    struct file* sFile = filesys_open(file);
    if(!sFile) /*maybe say file == null if doesn't work*/ 
      { 
	release_filesys();
	return -1;
      }
    int fd = add_process_file(sFile);
    release_filesys();
    return fd; 
  }
  NOT_REACHED();
}
							  
int filesize(int fd) {
  lock_filesys();
  struct file *file = get_process_file(fd);
  if(!file) {
    release_filesys();
    return -1;
  }
  int size = file_length(file);
  release_filesys();
  return size;
}

int read(int fd, void *buffer, unsigned size, uint32_t *stack_ptr) {
  void *temp_buffer;
  struct thread *current;
  struct supp_page *page;
  void *frame;
  if(is_user_vaddr(buffer)) {
    temp_buffer = pg_round_down(buffer);
    current = thread_current();
    page = get_supp_page(&current->supp_page_table, temp_buffer);

    /* Check if the stack needs to be expanded */
    if(page == NULL && (stack_ptr - 32) <= (uint32_t*) buffer) {
      if(PHYS_BASE - buffer > MAX_SIZE) {
	exit(-1);
      }

      if(pagedir_get_page(current->pagedir, temp_buffer) == NULL) {
	frame = allocate_frame(PAL_USER | PAL_ZERO);
	pagedir_set_page(current->pagedir, temp_buffer, frame, true);
      }

      int offset = PGSIZE;
      while(is_user_vaddr(temp_buffer + offset) && (pagedir_get_page(current->pagedir, temp_buffer + offset)) == NULL) {
	frame = allocate_frame(PAL_USER | PAL_ZERO);
	pagedir_set_page(current->pagedir, temp_buffer + offset, frame, true);
	offset += PGSIZE;
      }
    }
    if(fd == STDIN_FILENO)
      {
	lock_filesys();
	unsigned i;
	uint8_t *input = (uint8_t*) buffer;
	for(i=0; i< size; i++)
	  { 
	    input[i]=input_getc();
	  }
	release_filesys();
	return size;
      }
      struct file* file = get_process_file(fd);
      if(!file)
	{
	  release_filesys();
	  return -1;
	}
      int bytes = file_read(file, buffer, size); /* check file.h*/
      release_filesys();
      return bytes;
  }
  else {
    exit(-1);
  }
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd == STDIN_FILENO) {
    exit(-1);
  }
  if(check_ptr_access(buffer)) {
    if((buffer + size) < PHYS_BASE) {
      lock_filesys();
      if(fd == STDOUT_FILENO)
	{
	  putbuf(buffer,size);
	  release_filesys();
	  return size;
	}
      else {   
	struct file* file = get_process_file(fd);
	if(!file)
	  {
	    release_filesys();
	    return -1;
	  }
	int bytes = file_write(file,buffer,size); /*check file.h*/
	release_filesys();
	return bytes; 
      }
    }
  }
  NOT_REACHED();
}

void seek(int fd, unsigned position) {
  lock_filesys();
  struct file *file = get_process_file(fd);
  if(!file) {
    release_filesys();
    return;
  }
  file_seek(file, position);
  release_filesys();
}

unsigned tell(int fd) {
  lock_filesys();
  struct file *file = get_process_file(fd);
  if(!file) {
    release_filesys();
    return -1;
  }
  int offset = file_tell(file);
  release_filesys();
  return offset;
}

void close(int fd) {
  lock_filesys();
  close_process_file(fd);
  release_filesys();
}

bool add_process_mmap(struct supp_page* spte)
{
  struct mmap_file* mm = malloc(sizeof(struct mmap_file));
  if(!mm)
  {
    return false;
  }
  mm->spte = spte;
  mm->mapid = thread_current()->mapid;
  list_push_back(&thread_current()->mmap_list, &mm->elem);
  return true;
}

bool add_mmap_to_page_table(struct file* file, int32_t offset, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes)
{
  struct supp_page* spte = malloc(sizeof(struct supp_page));
  if(!spte)
  {
    return false;
  }

  spte->file = file;
  spte->offset =offset;
  spte->user_addr = upage;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->has_loaded = false;
  /*spte->type = MMAP;
  spte->pinned=false;*/
  spte->writable = true;

  if(!add_process_mmap(spte))
  {
    free(spte);
    return false;
  }

  /*if(hash_insert(&thread_current()->spt, &spte->elem))
  {
    spte->type = HASH_ERROR;
    return false;
  }*/
    return true;
}

int mmap(int fd, void* addr){
  struct file* old_file = get_process_file(fd);
  if(!old_file || !is_user_vaddr(addr) || /*addr < USER_VADDR_BOTTOM ||*/
    ((uint32_t) addr % PGSIZE) !=0)
  {
    return -1;
  }

  struct file* file = file_reopen(old_file);
  
  if(!file || file_length(old_file) == 0)
  {
    return -1;
  }
  /*adds two things to thread.h and inits in thread.c*/
  thread_current()->mapid += 1;
  int32_t offset = 0;
  uint32_t numBytes = file_length(file);
  while(numBytes>0)
  {
    uint32_t page_read_bytes;
    if(numBytes<PGSIZE)
    {
      page_read_bytes = numBytes;
    }
    else
    {
      page_read_bytes = PGSIZE;
    }
    uint32_t page_zero_bytes = PGSIZE - page_read_bytes;

    if(!add_mmap_to_page_table(file,offset,addr,page_read_bytes,page_zero_bytes))
    {
      munmap(thread_current()->mapid);
      return -1;
    }
    numBytes -= page_read_bytes;
    offset += page_read_bytes;
    addr += PGSIZE;
  }
  return thread_current()->mapid;

}

void remove_process_mmap(int mapping)
{
  struct thread* t = thread_current();
  struct list_elem *next, *e = list_begin(&t->mmap_list);
  struct file* f = NULL;
  int close = 0;

  while(e != list_end(&t->mmap_list))
  {
    next = list_next(e);
    struct mmap_file* mmFile = list_entry(e, struct mmap_file, elem);
    if(mmFile->mapid == mapping || mapping == -1)
    {
      /*mmFile->spte->pinned = true;*/
      if(mmFile->spte->has_loaded)
      {
        if(pagedir_is_dirty(t->pagedir, mmFile->spte->user_addr))
        {
          /*lock_filesys();*/
          file_write_at(mmFile->spte->file, mmFile->spte->user_addr,
            mmFile->spte->read_bytes, mmFile->spte->offset);
          /*release_filesys();*/
        }
        free_frame(pagedir_get_page(t->pagedir,mmFile->spte->user_addr));
        pagedir_clear_page(t->pagedir,mmFile->spte->user_addr);
      }
      /*if(mm->spte->type != HASH?)
      {
        hash_delete(&t->spt, &mm->spte->elem);
      }*/
      list_remove(&mmFile->elem);
      if(mmFile->mapid != close)
      {
        if(f)
        {
          lock_filesys();
          file_close(f);
          release_filesys();
        }
        close = mmFile->mapid;
        f=mmFile->spte->file;
      }
      free(mmFile->spte);
      free(mmFile);
    }
    e=next;
  }
    if(f)
    {
      lock_filesys();
      file_close(f);
      release_filesys();
    }
      
    
  }

void munmap(int mapping)
{
  remove_process_mmap(mapping);
}

