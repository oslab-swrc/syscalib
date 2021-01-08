#ifndef __FDTABLE_H__
#define __FDTABLE_H__

#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sched.h>
#include <semaphore.h>

#include "data_types.h"

#define QKEY (key_t)0xFFFF
#define MKEY (key_t)0xFF00

/**/
/*variables*/
/**/

int fdtable_init();
void fdtable_destroy();
thread_info* fdtable_add();
int fdtable_delete(int fd);
int fdtable_entry_delete(int fd);

//thread_info* fdtable_traversal(thread_info* head);

thread_info* fdtable_get_by_fd_all(int fd);
#ifdef __FILEIO__
	thread_info* fdtable_get_by_fd(int fd, boolean NetorFile);
#else
thread_info* fdtable_get_by_fd(int fd);

#endif
thread_info* fdtable_get_by_tid(pthread_t pthread);
void fdtable_forked(void* function, void* function2); /*called when process forked or cloned*/
int fdtable_getnumber();
int fdtable_isEmpty();
void fdtable_traversal();
void fdtable_traversal_reverse();
/*queue management*/

#endif
