/*SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note*/
/*Copyright (c) 2021 Konkuk University SSLAB*/

#include "fdtable.h"

int fdtable_init(){
/*initialize file descriptor table*/
	thr_num = 0;
	header = (thread_info*)calloc(1,sizeof(thread_info));

	if(header == NULL) return -1 ;
	tail = (thread_info*)calloc(1,sizeof(thread_info));

	if(tail == NULL){
		free(header); 
		return -1;
	}

	header->next = tail;
	header->prev = tail;
	tail ->next = header;
	tail->prev = header;
	header->thr_fd = -10;
	tail->thr_fd = -10;
	return 0;
}

int fdtable_init_pool(){
    /*initialize file descriptor table*/
    pool_thr_num = 0;
    pool_header = (thread_info*)calloc(1,sizeof(thread_info));
    if(pool_header == NULL) return -1 ;
    pool_tail = (thread_info*)calloc(1,sizeof(thread_info));

    if(pool_tail == NULL){
        free(pool_header);
        return -1;
    }

    pool_header->next = pool_tail;
    pool_header->prev = pool_tail;
    pool_tail ->next = pool_header;
    pool_tail->prev = pool_header;
    pool_header->thr_fd = -10;
    pool_tail->thr_fd = -10;

    return 0;
}

void fdtable_destroy(){
/*clean up all the memory*/
	thread_info * tmp = header ;
	while(tmp != tail){
		thread_info *obj = tmp;
		tmp = tmp->next;

        sem_destroy(&(obj->sem_thread));
        sem_destroy(&(obj->empty));
        sem_destroy(&(obj->empty2));
        sem_destroy(&(obj->full));
        sem_destroy(&(obj->full2));
        free(obj->message);

		free(obj);
	}

    sem_destroy(&(tail->sem_thread));
    sem_destroy(&(tail->empty));
    sem_destroy(&(tail->empty2));
    sem_destroy(&(tail->full));
    sem_destroy(&(tail->full2));
    free(tail->message);

    free(tail);
}

void fdtable_destroy_pool() {
/*clean up all the memory*/
    thread_info *tmp = pool_header;
    while (tmp != pool_tail) {
        thread_info *obj = tmp;
        tmp = tmp->next;

        sem_destroy(&(obj->sem_thread));
        sem_destroy(&(obj->empty));
        sem_destroy(&(obj->empty2));
        sem_destroy(&(obj->full));
        sem_destroy(&(obj->full2));
        free(obj->message);

        free(obj);
    }

    sem_destroy(&(pool_tail->sem_thread));
    sem_destroy(&(pool_tail->empty));
    sem_destroy(&(pool_tail->empty2));
    sem_destroy(&(pool_tail->full));
    sem_destroy(&(pool_tail->full2));
    free(pool_tail->message);

    free(pool_tail);
}

thread_info* fdtable_add(){
/*add given thread info to fdtable*/
	thread_info *new = (thread_info*)calloc(1,sizeof(thread_info));
	thread_info *next_node = header->next;
	if(new == NULL){
		return NULL;
	}else{
	    new->thr_fd = -11;
		new->pid = getpid();
		if(-1 == sem_init(&(new->sem_thread), 1, 1)){
			perror("Current Thread Semaphore Init Error\n");
//			exit(-EINVAL);
            exit(-1);
		}
		sem_init(&(new->empty), 1, 1);
		sem_init(&(new->full), 1, 0);
		sem_init(&(new->empty2), 1, 1);
		sem_init(&(new->full2), 1, 0);
		new->message = malloc(sizeof(args_data));
		memset(new->message, 0, sizeof(args_data));   // memset - cglee

        new->prev = header;
        new->next = next_node;
        header->next = new;
        next_node->prev = new;
		thr_num++;
		return new;
	}
}

thread_info* fdtable_get_by_fd_all(int fd){
    thread_info *tmp = header->next;

    while(tmp != tail && tmp != NULL){
        if(tmp->thr_fd == fd){
            return tmp;
        }
        else tmp = tmp->next;
    }
    return NULL;
}

#ifdef __FILEIO__
thread_info* fdtable_get_by_fd(int fd, boolean NetorFile){
/*returns thread that matches given fd */
	thread_info *tmp = header->next ;

	while(tmp != tail && tmp != NULL){
		if(tmp->thr_fd == fd && tmp->NetorFile == NetorFile){
		   return tmp;
		}
		else tmp = tmp->next;
	}
	return NULL ;
}

#else
thread_info* fdtable_get_by_fd(int fd){
/*returns thread that matches given fd */
	thread_info *tmp = header->next ;

	while(tmp != tail && tmp != NULL){
		if(tmp->thr_fd == fd){
			return tmp;
		}
		tmp = tmp->next ;
	}
	return NULL ;
}
#endif

thread_info* fdtable_get_by_tid(pthread_t pthread){
	thread_info *tmp = header ;
	while(tmp != tail && tmp != NULL){
		if(tmp->p_thread == pthread){
		 return tmp;
		}
		tmp = tmp->next ;
	}
	return NULL ;
}

int fdtable_delete(int fd) {
/*delete thread with given fd from fdtable*/
    thread_info *tmp = fdtable_get_by_fd_all(fd);

    if (tmp != NULL) {
        thread_info *next_node = tmp->next;
        thread_info *prev_node = tmp->prev;

        if (next_node != NULL && prev_node != NULL) {
            prev_node->next = next_node;
            next_node->prev = prev_node;
            tmp ->next = NULL;
            tmp ->prev = NULL;

            sem_destroy(&(tmp->sem_thread));
            sem_destroy(&(tmp->empty));
            sem_destroy(&(tmp->empty2));
            sem_destroy(&(tmp->full));
            sem_destroy(&(tmp->full2));
            memset(tmp->message, 0, sizeof(args_data));      // memset - cglee
            free(tmp->message);
            memset(tmp, 0, sizeof(args_data));              // memset - cglee
            free(tmp);
            thr_num--;
            return 0;
        } else {
            return -1;
        }

    } else return -1;
}

int fdtable_entry_delete(int fd){
    thread_info *tmp = fdtable_get_by_fd_all(fd);
    thread_info *tmp2;

    if(tmp != NULL) {
        thread_info *next_node = tmp->next;
        thread_info *prev_node = tmp->prev;

        if (next_node != NULL && prev_node != NULL) {
            prev_node->next = next_node;
            next_node->prev = prev_node;
            tmp ->next = NULL;
            tmp ->prev = NULL;
            thr_num--;
        } else {
            return 1;
        }
    }
    return 0;
}

void fdtable_traversal(){
	FILE* log_fd;										// changyu-lee : for log
	log_fd = fopen("/home/hadoop/Function_errorlog", "a+");		    // for parents -cglee
	//else log_fd =  fopen("/home/hadoop/Fdtable_log_child", "a+");		    // for child -cglee
	thread_info *tmp = header->next;
	fprintf(log_fd, "------------------------fd table---------------------\n");

	while(tail != tmp){
		fprintf(log_fd, "fd :: %d d : %lu\n", tmp->thr_fd, tmp->p_thread); //changyu-lee : for check fd_table elements
		tmp = tmp->next ;
	}
    fprintf(log_fd, "------------------------end table---------------------\n");
	fclose(log_fd);
}

void fdtable_traversal_reverse(){
    FILE* log_fd;										// changyu-lee : for log
    log_fd = fopen("/home/hadoop/Function_errorlog", "a+");		    // for parents -cglee
    //else log_fd =  fopen("/home/hadoop/Fdtable_log_child", "a+");		    // for child -cglee
    thread_info *tmp = tail->prev;
    fprintf(log_fd, "------------------------fd table---------------------\n");

    while(header != tmp){
        fprintf(log_fd, "fd :: %d tid : %lu\n", tmp->thr_fd, tmp->p_thread); //changyu-lee : for check fd_table elements
        tmp = tmp->prev ;
    }
    fprintf(log_fd, "------------------------end table---------------------\n");
    fclose(log_fd);
}


void fdtable_forked(void* function, void* function2){
 /*called when process forked or cloned*/
	pthread_t thr_id ;
	header->pid = getpid();
	thread_info* tmp = header->next ;
	/*reproduce thread, and ipc key value*/
	while(tmp != tail){
        sem_init(&(tmp->sem_thread), 1, 1);
        if (tmp->thr_fd == -10000) {
            tmp->pid = getpid();
            thr_id = pthread_create(&(tmp->p_thread), NULL, function2, NULL);
            tmp->message = malloc(sizeof(args_data));
            sem_init(&(tmp->empty), 1, 1);
            sem_init(&(tmp->full), 1, 0);
            sem_init(&(tmp->empty2), 1, 1);
            sem_init(&(tmp->full2), 1, 0);
        } else {
            tmp->pid = getpid();
            thr_id = pthread_create(&(tmp->p_thread), NULL, function, NULL);
            tmp->message = malloc(sizeof(args_data));
            sem_init(&(tmp->empty), 1, 1);
            sem_init(&(tmp->full), 1, 0);
            sem_init(&(tmp->empty2), 1, 1);
            sem_init(&(tmp->full2), 1, 0);
        }
//        sem_post(&(tmp->sem_thread));
        tmp = tmp->next;
    }

    tmp = pool_header->next;
    while(tmp != pool_tail){
        sem_init(&(tmp->sem_thread), 1, 1);
        if (tmp->thr_fd == -10000) {
            tmp->pid = getpid();
            thr_id = pthread_create(&(tmp->p_thread), NULL, function2, NULL);
            tmp->message = malloc(sizeof(args_data));
            sem_init(&(tmp->empty), 1, 1);
            sem_init(&(tmp->full), 1, 0);
            sem_init(&(tmp->empty2), 1, 1);
            sem_init(&(tmp->full2), 1, 0);
        } else {
            tmp->pid = getpid();
            thr_id = pthread_create(&(tmp->p_thread), NULL, function, NULL);
            tmp->message = malloc(sizeof(args_data));
            sem_init(&(tmp->empty), 1, 1);
            sem_init(&(tmp->full), 1, 0);
            sem_init(&(tmp->empty2), 1, 1);
            sem_init(&(tmp->full2), 1, 0);
        }
        tmp = tmp->next;
    }

}

int fdtable_getnumber(){
	return thr_num ;
}

int fdtable_isEmpty(){
	if(thr_num > 0) return 0;
	else return 1 ;
}


int fdtable_to_pool(int fd){
    int ret = 2; // 0 : to pool,  1 : delete, 2 : error

    thread_info *tmp = fdtable_get_by_fd_all(fd);
    if(pool_thr_num >= POOL_LIMIT){

        thread_info *next_node = tmp->next;
        thread_info *prev_node = tmp->prev;

        if (next_node != NULL && prev_node != NULL) {
/*
            prev_node->next = next_node;
            next_node->prev = prev_node;

            sem_destroy(&(tmp->sem_thread));
            sem_destroy(&(tmp->empty));
            sem_destroy(&(tmp->empty2));
            sem_destroy(&(tmp->full));
            sem_destroy(&(tmp->full2));
            memset(tmp->message, 0, sizeof(args_data));      // memset - cglee
            free(tmp->message);
            memset(tmp, 0, sizeof(args_data));              // memset - cglee
            free(tmp);
*/
            thr_num--;

            ret = 1;
        }
    }
    else if(tmp != NULL) {
        tmp->thr_fd = -1;

        thread_info *next_node = tmp->next;
        thread_info *prev_node = tmp->prev;

        if (next_node != NULL && prev_node != NULL) {

            prev_node->next = next_node;
            next_node->prev = prev_node;

            tmp ->next = pool_header->next;
            tmp->next->prev = tmp;
            tmp ->prev = pool_header;
            pool_header->next = tmp;

            thr_num--;
            pool_thr_num++;

            ret = 0;
        }
        else {
            exit(-1);
        }
    }

    return ret;
}

thread_info* fdtable_from_pool(){
    thread_info *tmp = NULL;
    if(pool_header->next != pool_tail){
        tmp = pool_header->next;

        pool_header->next = tmp->next;
        tmp->next->prev = pool_header;

        tmp->prev = header;
        tmp->next = header->next;
        header->next = tmp;
        tmp->next->prev = tmp;

        pool_thr_num--;
        thr_num++;
        return tmp;
    }
    return NULL;
}
