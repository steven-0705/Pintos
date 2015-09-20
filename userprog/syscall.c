#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	unint32_t *p = f->esp;
	unint32_t *arg = 0;
	unint32_t *arg2 = 0;
	unint32_t *arg3 = 0;
	if(p !=NULL && is_user_vaddr(p) && p < PHYSBASE){
		switch(&p)
		{
			case SYS_HALT:
				 shutdown_configure (SHUTDOWN_POWER_OFF);
		
			case SYS_EXEC:
				arg = *(p + 1);
				break;
			case SYS_WAIT:
				arg = *(p + 1);
				break;
			case SYS_REMOVE:
				arg = *(p + 1);
				break;
			case SYS_OPEN:
				arg = *(p + 1);
				break;
			case SYS_FILESIZE:
				arg = *(p + 1);
				break;
			case SYS_TELL:
				arg = *(p + 1);
				break;
			case SYS_CLOSE:
				arg = *(p + 1);
				break;
			case SYS_EXIT:
				arg = *(p + 1);
				break;
			case SYS_CREATE:
				arg = *(p + 1);
				arg2 = *(p + 2);
				break;
			case SYS_SEEK:
				arg = *(p + 1);
				arg2 = *(p + 2);
				break;
			
			case SYS_WRITE:
				arg = *(p + 1);
				arg2 = *(p + 2);
				arg3 = *(p + 3);
			if(arg3 < PHYBASE){
				}
				break;
			case SYS_READ:
				arg = *(p + 1);
				arg2 = *(p + 2);
				arg3 = *(p + 3);
			if(arg3 < PHYBASE){
				}
				break;
			default:
				break;
		}
	
  
  thread_exit ();
}
