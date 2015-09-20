#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t *p = (uint32_t*)f->esp;
	uint32_t *arg = 0;
	uint32_t *arg2 = 0;
	uint32_t *arg3 = 0;
	if(p !=NULL && is_user_vaddr(p) && p < PHYS_BASE){
		switch((uint32_t)&p)
		{
			case SYS_HALT:
				 //shutdown_configure (SHUTDOWN_POWER_OFF);
				break;
			case SYS_EXEC:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_WAIT:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_REMOVE:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_OPEN:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_FILESIZE:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_TELL:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_CLOSE:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_EXIT:
				arg = (uint32_t)*(p + 1);
				break;
			case SYS_CREATE:
				arg = (uint32_t)*(p + 1);
				arg2 = (uint32_t)*(p + 2);
				break;
			case SYS_SEEK:
				arg = (uint32_t)*(p + 1);
				arg2 = (uint32_t)*(p + 2);
				break;
			
			case SYS_WRITE:
				arg = (uint32_t)*(p + 1);
				arg2 = (uint32_t)*(p + 2);
				arg3 = (uint32_t)*(p + 3);
			if(arg3 < PHYS_BASE){
				f->eax = -1;
				}
				break;
			case SYS_READ:
				arg = (uint32_t)*(p + 1);
				arg2 = (uint32_t)*(p + 2);
				arg3 = (uint32_t)*(p + 3);
			if(arg3 < PHYS_BASE){
				f->eax = -1;
				}
				break;
			default:
				break;
		}
	}
  
  thread_exit ();
}
