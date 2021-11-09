/*SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note*/
/*Copyright (c) 2021 Konkuk University SSLAB*/

#include "ld_preload.h"
#include <sys/time.h>
#include <signal.h>

#ifndef O_NONBLOCK
#define O_NONBLOCK	0x0004
#define O_ASYNC     0x0040
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */

#define DYNAMIC_THREAD_SYSCALLCOUNT	10

#endif

static void wrap_init(void) __attribute__((constructor));     // constructor
static void end(void) __attribute__((destructor));            // destructor


static void wrap_init(void)
{
    if(fdtable_init() == -1){
        exit(-EINVAL);
    }

    if(fdtable_init_pool() == -1){
        exit(-EINVAL);
    }

    if(-1 == pthread_rwlock_init(&table_rwlock, NULL)){     //add for rwlock
        perror("Forwarding Semaphore Init Error\n");
        exit(-EINVAL);
    }

    socket0_cpu = 0;
    socket1_cpu = 0;
    file_cpu = 16;
    net_cpu = 13;
    original_select = dlsym(RTLD_NEXT, "select");
    original_socket = dlsym(RTLD_NEXT, "socket");
    original_bind = dlsym(RTLD_NEXT, "bind");
    original_listen = dlsym(RTLD_NEXT, "listen");
    original_accept = dlsym(RTLD_NEXT, "accept");
    original_connect = dlsym(RTLD_NEXT, "connect");
    original_send = dlsym(RTLD_NEXT, "send");
    original_recv = dlsym(RTLD_NEXT, "recv");
    original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    original_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    original_close = dlsym(RTLD_NEXT, "close");
    original_read = dlsym(RTLD_NEXT, "read");
    original_write = dlsym(RTLD_NEXT, "write");
    original_poll = dlsym(RTLD_NEXT, "poll");
    original_ppoll = dlsym(RTLD_NEXT, "ppoll");
    original_sendto = dlsym(RTLD_NEXT, "sendto");
    original_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    original_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    original_getsockname = dlsym(RTLD_NEXT, "getsockname");
    original_getpeername = dlsym(RTLD_NEXT, "getpeername");
    original_shutdown = dlsym(RTLD_NEXT, "shutdown");
    original_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
    original_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    original_epoll_create = dlsym(RTLD_NEXT, "epoll_create");
    original_socketpair = dlsym(RTLD_NEXT, "socketpair");
    original_open = dlsym(RTLD_NEXT, "open");
    original_creat = dlsym(RTLD_NEXT, "creat");
    original_open64 = dlsym(RTLD_NEXT, "open64");
    original_openat = dlsym(RTLD_NEXT, "openat");
    original_lseek = dlsym(RTLD_NEXT, "lseek");
    original_stat = dlsym(RTLD_NEXT, "stat");
    original_openat64 = dlsym(RTLD_NEXT, "openat64");
    original_lseek64 = dlsym(RTLD_NEXT, "lseek64");
    original_stat64 = dlsym(RTLD_NEXT, "stat64");
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fork = dlsym(RTLD_NEXT, "fork");
}

/*
static void end(void){
    thread_info* tmp = header->next ;
    thread_info* tmp2;

    fdtable_destroy();
    fdtable_destroy_pool();

    pthread_rwlock_destroy(&table_rwlock);
}
*/

long getMicrotime(){					// for timestamp
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
}

void *syscall_thread()
{
    args_data send_data ;
    retval_data recv_data ;

    int loop_break = 0;         // for delete -1 table - cglee
    int old_errno = 0;
    int flag;                   // for NIO->blocking IO
    thread_info *sock;          /*thread info per socket*/
    int ret ;

    int syscall_counter = 0; //for dynamic thread affinity

    char * str;
    /******************************** Allocation CPU ****************************************/
#ifdef __ONE__
    cpu = 1;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif

#ifdef __RR__
    if(ONE_NODE <= cpu)
		cpu = 2;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif

#ifdef __RR2__
    if(TWO_NODE <= cpu)
		cpu = ONE_NODE+1;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif
#ifdef __DYNAMIC__
    set_cpu(1, 0);
#endif


#ifdef __WITHIN__
    cpu = set_affinity_within(0);
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif

//    sem_wait(&sem_fdtable);           // disable lock - cgl //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
    sock = fdtable_get_by_tid(pthread_self());

    if(sock == NULL){
        pthread_rwlock_unlock(&table_rwlock);
        return NULL;
    }
    pthread_rwlock_unlock(&table_rwlock);

    send_data.request_type = -1;
#ifdef __FILEIO__
    set_cpu(1, sock->NetorFile);
#endif
//    sem_post(&sem_fdtable);           // disable lock - cgl //disable for rwlock
    if(sock->pid == getpid()){
//        sem_post(&(sock->sem_thread));
        while(send_data.request_type != TYPE_CLOSE && send_data.request_type != TYPE_SHUTDOWN){
            send_data = CPART_recv_from_app(send_data, sock);
            recv_data.request_type = send_data.request_type;
            recv_data.thr_errno = 0;

            syscall_counter++;
            /* call set_cpu() for dynamic thread affinity */
            if(syscall_counter >= DYNAMIC_THREAD_SYSCALLCOUNT){
                syscall_counter = 0;
                set_cpu(1, sock->NetorFile);
            }

            switch(send_data.request_type){

                case TYPE_SOCKET:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_socket)(send_data.socket.domain, send_data.socket.type, send_data.socket.protocol);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;

                case TYPE_BIND:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_bind)(send_data.bind.socket, send_data.bind.address, send_data.bind.address_len);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;

                case TYPE_LISTEN:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_listen)(send_data.listen.sockfd, send_data.listen.backlog);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;

                case TYPE_ACCEPT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_accept)(send_data.accept.socket, send_data.accept.addr, send_data.accept.addrlen);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_CONNECT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_connect)(send_data.connect.socket, send_data.connect.address, send_data.connect.address_len);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SEND:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_send)(send_data.send.socket, send_data.send.buffer, send_data.send.length, send_data.send.flags);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_RECV:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_recv)(send_data.recv.socket, send_data.recv.buf, send_data.recv.length, send_data.recv.flags);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SETSOCKOPT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_setsockopt)(send_data.setsockopt.socket, send_data.setsockopt.level, send_data.setsockopt.option_name, send_data.setsockopt.option_value, send_data.setsockopt.option_len);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_GETSOCKOPT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_getsockopt)(send_data.getsockopt.socket, send_data.getsockopt.level, send_data.getsockopt.option_name, send_data.getsockopt.buf, send_data.getsockopt.addrlen);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_READ:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_read)(send_data.read.fildes, send_data.read.buf, send_data.read.nbyte);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_WRITE:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_write)(send_data.write.fildes, send_data.write.buf, send_data.write.nbyte);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;

                case TYPE_CLOSE:

//                    old_errno = errno;
//                    errno = 0;
//                    recv_data.return_value = (*original_close)(send_data.fildes);
//                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
//                    else errno = old_errno;                         // errno not changed
                    break;

                case TYPE_POLL:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_poll)(send_data.poll.ufds, send_data.poll.nfds, send_data.poll.timeout);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_PPOLL:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_ppoll)(send_data.ppoll.ufds, send_data.ppoll.nfds, send_data.ppoll.timeout_ts, send_data.ppoll.sigmask);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_EPOLL_WAIT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_epoll_wait)(send_data.epoll_wait.epfd, send_data.epoll_wait.events, send_data.epoll_wait.maxevents, send_data.epoll_wait.timeout);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_EPOLL_CREATE:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_epoll_create)(send_data.epoll_create.size);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_EPOLL_CTL:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_epoll_ctl)(send_data.epoll_ctl.epfd, send_data.epoll_ctl.op, send_data.epoll_ctl.fd, send_data.epoll_ctl.events);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SOCKETPAIR:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_socketpair)(send_data.socketpair.domain, send_data.socketpair.type, send_data.socketpair.protocol, send_data.socketpair.sv);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SENDTO:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_sendto)(send_data.sendto.socket, send_data.sendto.buffer, send_data.sendto.length, send_data.sendto.flags, send_data.sendto.address, send_data.sendto.address_len);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_RECVFROM:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_recvfrom)(send_data.recvfrom.socket, send_data.recvfrom.buf, send_data.recvfrom.length, send_data.recvfrom.flags, send_data.recvfrom.addr, send_data.recvfrom.addrlen);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SENDMSG:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_sendmsg)(send_data.sendmsg.socket, send_data.sendmsg.msg, send_data.sendmsg.flags);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_RECVMSG:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_size = (*original_recvmsg)(send_data.recvmsg.socket, send_data.recvmsg.msg_rcv, send_data.recvmsg.flags);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_SHUTDOWN:
//                    old_errno = errno;
//                    errno = 0;
//                    recv_data.return_size = (*original_shutdown)(send_data.shutdown.socket, send_data.shutdown.flags);
//                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
//                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_GETSOCKNAME:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_getsockname)(send_data.getsockname.socket, send_data.getsockname.addr, send_data.getsockname.addrlen);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_GETPEERNAME:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_getpeername)(send_data.getpeername.socket, send_data.getpeername.addr, send_data.getpeername.addrlen);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_OPEN:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_open)(send_data.open.pathname, send_data.open.flags, send_data.open.mode);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_OPENAT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_openat)(send_data.openat.dirfd, send_data.openat.pathname, send_data.openat.flags, send_data.openat.mode);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    if(recv_data.return_value == -1) loop_break = 1;  // for break when return -1 - cglee
                    break;
                case TYPE_LSEEK:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_lseek)(send_data.lseek.fd, send_data.lseek.offset, send_data.lseek.whence);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_LSEEK64:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_lseek64)(send_data.lseek.fd, send_data.lseek.offset, send_data.lseek.whence);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_STAT:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_stat)(send_data.stat.path, send_data.stat.buf);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                case TYPE_STAT64:
                    old_errno = errno;
                    errno = 0;
                    recv_data.return_value = (*original_stat64)(send_data.stat.path, send_data.stat.buf);
                    if(errno != 0) recv_data.thr_errno = errno;     // set changed errno
                    else errno = old_errno;                         // errno not changed
                    break;
                default:
                    break;
            }
            CPART_send_to_app(recv_data, sock);

            if(loop_break == 1){        // for break when return -1 - cgl
                return NULL;
            }

        }//End of while
    }
    else{
//        sem_post(&(sock->sem_thread));
    }
    return NULL;
}


void *ku_select()
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    thread_info *sel; /*thread per select*/


    //-******************************** Allocation CPU ****************************************-/
#ifdef __ONE__
    cpu = 1;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif

#ifdef __RR__
    if(ONE_NODE <= cpu)
		cpu = 1;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif

#ifdef __RR2__
    if(TWO_NODE <= cpu)
		cpu = ONE_NODE+1;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
#endif
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
    sel = fdtable_get_by_tid(pthread_self());
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
#ifdef __FILEIO__
    set_cpu(1, sel->NetorFile);
#endif
    while(1){
        send_data = CPART_recv_from_app(send_data, sel);
        recv_data.request_type = send_data.request_type;
        recv_data.return_value = (*original_select)(send_data.select.n, send_data.select.readfds, send_data.select.writefds, send_data.select.exceptfds, send_data.select.stimeout);
        CPART_send_to_app(recv_data, sel);
    }
}


int close(int fildes)
{
    int ret_flag;
    int ret; //
    thread_info* tmp;
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    int func_errno = errno;

    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd_all(fildes);
#else
    tmp = fdtable_get_by_fd(fildes);
#endif

    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_close)(fildes);
    }
    else{
        /*
        send_data.request_type = TYPE_CLOSE;
        send_data.fildes = fildes;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
*/
         /*
        pthread_rwlock_wrlock(&table_rwlock);
        pthread_join(tmp->p_thread, (void **)&status);          // do we need to wait for thread?
        fdtable_delete(fildes);

        pthread_rwlock_unlock(&table_rwlock);
*/
        pthread_rwlock_wrlock(&table_rwlock);
        //fdtable_entry_delete(socket);
        ret_flag = fdtable_to_pool(fildes);
        if(ret_flag == 1){
            thread_info *next_node = tmp->next;
            thread_info *prev_node = tmp->prev;

            prev_node->next = next_node;
            next_node->prev = prev_node;
/*
            send_data.request_type = TYPE_CLOSE;

            CPART_send_to_thread(send_data, tmp);
            CPART_recv_from_thread(recv_data_p, tmp);
*/
            ret = (*original_close)(fildes);

            sem_destroy(&(tmp->sem_thread));
            sem_destroy(&(tmp->empty));
            sem_destroy(&(tmp->empty2));
            sem_destroy(&(tmp->full));
            sem_destroy(&(tmp->full2));
            memset(tmp->message, 0, sizeof(args_data));      // memset - cglee
            free(tmp->message);
            //pthread_kill(tmp->p_thread, SIGTERM);
            memset(tmp, 0, sizeof(args_data));              // memset - cglee
            free(tmp);

            pthread_rwlock_unlock(&table_rwlock);
            return ret;
        }
        pthread_rwlock_unlock(&table_rwlock);

        return (*original_close)(fildes);
    }
}

int creat(const char *pathname, mode_t mode){
    int thr_id;
    int num = 1;
    thread_info *tmp;
    int ret = 0;
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    int func_errno = errno;

    int thread_flag = 0;


    if(strcmp(pathname, "/dev/tty")==0){
        return (*original_creat)(pathname, mode);
    }

    errno = 0;
    ret = (*original_creat)(pathname, mode);
    if(errno != 0) func_errno = errno;
    else errno = func_errno;
    if(ret < 3) return ret;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_wrlock(&table_rwlock);


    if(fdtable_get_by_fd_all(ret) != NULL || ret < 0){
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    else if(fdtable_getnumber() < MAXTHREAD){
        tmp = fdtable_from_pool();
        if(tmp == NULL){
            tmp  = fdtable_add();
            thread_flag = 1;
        }

//        sem_post(&sem_fdtable);                 // disable for fdtable_forked() //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
//        sem_wait(&(tmp->sem_thread));
        tmp->pid = getpid();
        tmp->NetorFile = 1;
        if(thread_flag == 1){
            thr_id = pthread_create(&(tmp->p_thread), NULL, syscall_thread, NULL); // need to?
            pthread_detach(tmp->p_thread);
        }
//        sem_wait(&(tmp->sem_thread));
        tmp->thr_fd = ret;
//        sem_post(&(tmp->sem_thread));
        if(thr_id < 0){
            perror("pthread_create error");
        }
    }
    else{
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    errno = func_errno;
    return ret;
}


/*old*/
int socket(int domain, int type, int protocol)
{
    int thr_id;
    int num = 1;
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    thread_info *tmp;
    int ret = 0;
    int flag = 0;
    int thread_flag = 0;

    int func_errno = errno;
    original_socket = dlsym(RTLD_NEXT, "socket");

    errno = 0;

//    return (*original_socket)(domain, type, protocol);


    ret = (*original_socket)(domain, type, protocol);
    // check O_ASYNC
    if(errno != 0){
        func_errno = errno;
    }
    else{
        errno = func_errno;
    }
    if(ret < 3) return ret;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_wrlock(&table_rwlock);
    if(fdtable_get_by_fd_all(ret) != NULL || ret < 0){
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }

    else if(fdtable_getnumber() < MAXTHREAD){
        tmp = fdtable_from_pool();
        if(tmp == NULL){
            tmp  = fdtable_add();
            thread_flag = 1;
        }

//        sem_post(&sem_fdtable);                 // disable for fdtable_forked() //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        tmp->pid = getpid();
        tmp->NetorFile = 0;
        if(thread_flag == 1){
            thr_id = pthread_create(&(tmp->p_thread), NULL, syscall_thread, NULL); // need to?
            pthread_detach(tmp->p_thread);
        }
//        sem_wait(&(tmp->sem_thread));
        tmp->thr_fd = ret;
//        sem_post(&(tmp->sem_thread));
        if(thr_id < 0){
            perror("pthread_create error");
        }
    }
    else{
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    errno = func_errno;
    return ret;
}

#ifdef __FILEIO__
/*old*/
int open(const char *path, int flags, mode_t mode)
{
	int thr_id;
	int num = 1;
	thread_info *tmp;
	int ret = 0;
	args_data send_data = {1, 0};
	retval_data recv_data = {1, 0, 0};
	retval_data* recv_data_p;
	recv_data_p = &recv_data;
    int func_errno = errno;

    int thread_flag = 0;


	if(strcmp(path, "/dev/tty")==0){
        return (*original_open)(path, flags, mode);
	}

    errno = 0;
    ret = (*original_open)(path, flags, mode);
    if(errno != 0) func_errno = errno;
    else errno = func_errno;
    if(ret < 3) return ret;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_wrlock(&table_rwlock);


    if(fdtable_get_by_fd_all(ret) != NULL || ret < 0){
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    else if(fdtable_getnumber() < MAXTHREAD){
        tmp = fdtable_from_pool();
        if(tmp == NULL){
            tmp  = fdtable_add();
            thread_flag = 1;
        }

//        sem_post(&sem_fdtable);                 // disable for fdtable_forked() //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
//        sem_wait(&(tmp->sem_thread));
        tmp->pid = getpid();
        tmp->NetorFile = 1;
        if(thread_flag == 1){
            thr_id = pthread_create(&(tmp->p_thread), NULL, syscall_thread, NULL); // need to?
            pthread_detach(tmp->p_thread);
        }
//        sem_wait(&(tmp->sem_thread));
        tmp->thr_fd = ret;
//        sem_post(&(tmp->sem_thread));
        if(thr_id < 0){
            perror("pthread_create error");
        }
    }
    else{
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    errno = func_errno;
    return ret;
}

off_t openat(int dirfd, const char *pathname, int flags, mode_t mode){
	int thr_id;
	int num = 1;
	args_data send_data = {1, 0};
	retval_data recv_data = {1, 0, 0};
	retval_data* recv_data_p;
	recv_data_p = &recv_data;

	int ret = 0;
    int func_errno = errno;
    int thread_flag = 0;
	thread_info *tmp;

    errno = 0;
    ret = (*original_openat)(dirfd, pathname, flags, mode);
    if(errno != 0) func_errno = errno;
    else errno = func_errno;
    func_errno = errno;
//    sem_wait(&sem_fdtable);   //disable for rwlock
    pthread_rwlock_wrlock(&table_rwlock);

    if(fdtable_get_by_fd_all(ret) != NULL || ret < 0){
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    else if(ret >0 && (fdtable_getnumber() < MAXTHREAD)){
        tmp = fdtable_from_pool();
        if(tmp == NULL){
            tmp  = fdtable_add();
            thread_flag = 1;
        }

//        sem_post(&sem_fdtable);                 // disable for fdtable_forked() //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
//        sem_wait(&(tmp->sem_thread));           // tmp disable
        tmp->pid = getpid();
#ifdef __FILEIO__
        tmp->NetorFile = 1;
#endif
        if(thread_flag == 1){
            thr_id = pthread_create(&(tmp->p_thread), NULL, syscall_thread, NULL); // need to?
            pthread_detach(tmp->p_thread);
        }
//        sem_wait(&(tmp->sem_thread));
        tmp->thr_fd = ret;
//        sem_post(&(tmp->sem_thread));
//		sem_post(&sem_fdtable);
        if(thr_id < 0){
            perror("pthread_create error");
        }
    }
    else{
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }
    errno = func_errno;
    return ret;
}

off_t lseek(int fd, off_t offset, int whence){
		thread_info* tmp;
		args_data send_data = {1, 0};
		retval_data recv_data = {1, 0, 0};
		retval_data* recv_data_p;
		recv_data_p = &recv_data;
		int func_errno = errno;

//		sem_wait(&sem_fdtable); //disable for rwlock
        pthread_rwlock_rdlock(&table_rwlock);
		tmp = fdtable_get_by_fd(fd, 1);
//		sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);

		if(tmp == NULL)
		{
	    	errno = func_errno;
			return (*original_lseek)(fd, offset, whence);
		}
		else
		{
			if(tmp->NetorFile == 0) return -1;

			send_data.request_type = TYPE_LSEEK;
			send_data.lseek.fd = fd;
			send_data.lseek.offset = offset;
			send_data.lseek.whence = whence;

			CPART_send_to_thread(send_data, tmp);
			CPART_recv_from_thread(recv_data_p, tmp);

		    if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
		    else errno = func_errno;
			return recv_data.return_value;
		}
}


void *stat_syscall()
{
	args_data send_data = {1, 0};
	retval_data recv_data = {1, 0, 0};

	thread_info *stat; /*thread per stat*/

	//-******************************** Allocation CPU ****************************************-/
	#ifdef __ONE__
	cpu = 1;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	#endif
	#ifdef __RR__
	if(ONE_NODE <= cpu)
		cpu = 1;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	#endif

	#ifdef __RR2__
	if(TWO_NODE <= cpu)
		cpu = ONE_NODE+1;
	else
		cpu++;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	#endif

//	sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
	stat = fdtable_get_by_tid(pthread_self());
//	sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

	#ifdef __FILEIO__
		set_cpu(1, stat->NetorFile);
	#endif


	send_data = CPART_recv_from_app(send_data, stat);
	recv_data.request_type = send_data.request_type;
	recv_data.return_value = (*original_stat)(send_data.stat.path, send_data.stat.buf);
	CPART_send_to_app(recv_data, stat);
    errno = recv_data.thr_errno;

	return NULL;
}

ssize_t read(int fildes, void *buf, size_t nbyte)
{
	thread_info* tmp;
	args_data send_data = {1, 0};
	retval_data recv_data = {1, 0, 0};
	retval_data* recv_data_p;
	recv_data_p = &recv_data;
	int func_errno = errno;

//	sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
	tmp = fdtable_get_by_fd(fildes, 1);
//	sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

	if(tmp == NULL)
	{
	    errno = func_errno;
		return (*original_read)(fildes, buf, nbyte);
	}
	else
	{
		send_data.request_type = TYPE_READ;
		send_data.read.fildes = fildes;
		send_data.read.buf = buf;
		send_data.read.nbyte = nbyte;


		CPART_send_to_thread(send_data, tmp);

		CPART_recv_from_thread(recv_data_p, tmp);
		if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
		else errno = func_errno;
		return recv_data.return_size;
	}
}

ssize_t write(int fildes, const void *buf, size_t nbyte)
{
	thread_info* tmp;
	args_data send_data = {1, 0};
	retval_data recv_data = {1, 0, 0};
	retval_data* recv_data_p;
	recv_data_p = &recv_data;
	int func_errno = errno;

//	sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
	tmp = fdtable_get_by_fd(fildes, 1);

//	sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

	if(tmp == NULL)
	{
	    errno = func_errno;
		return (*original_write)(fildes, buf, nbyte);
	}
	else
	{
		send_data.request_type = TYPE_WRITE;
		send_data.write.fildes = fildes;
		send_data.write.buf = buf;
		send_data.write.nbyte = nbyte;

		CPART_send_to_thread(send_data, tmp);
		CPART_recv_from_thread(recv_data_p, tmp);

		if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
		else errno = func_errno;
		return recv_data.return_size;
	}
}


#endif

int bind(int socket, const struct sockaddr* address, socklen_t address_len)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    thread_info* tmp ;
    recv_data_p = &recv_data;
    int func_errno = errno;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);


    if(tmp == NULL){
        errno = func_errno;
        return (*original_bind)(socket, address, address_len);
    }
    else{
        send_data.request_type = TYPE_BIND;
        send_data.bind.socket = socket;
        send_data.bind.address = address;
        send_data.bind.address_len = address_len;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        errno = recv_data_p->thr_errno;

        return recv_data.return_value;
    }
}

int listen(int sockfd, int backlog)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(sockfd, 0);
#else
    tmp = fdtable_get_by_fd(sockfd);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_listen)(sockfd, backlog);
    }
    else{
        send_data.request_type = TYPE_LISTEN;
        send_data.listen.sockfd = sockfd;
        send_data.listen.backlog = backlog;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}


int accept(int socket, struct sockaddr* addr, socklen_t *addrlen)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p = &recv_data;
    int thr_id;
    int num = 1;
    thread_info* tmp;
    thread_info* tmp2;
    int func_errno = 0;
    int ret=0;

    func_errno = errno;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
    tmp = fdtable_get_by_fd(socket, 0);
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL){        // no table for parameter socket
        errno = func_errno;
        return (*original_accept)(socket, addr, addrlen);
    }
    else {                   // parameter socket has fd table entry
        send_data.request_type = TYPE_ACCEPT;
        send_data.accept.socket = socket;
        send_data.accept.addr = addr;
        send_data.accept.addrlen = addrlen;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);

        if (recv_data_p->return_value > 0 && fdtable_get_by_fd_all(ret) == NULL) {              // when accept() success
//            sem_wait(&sem_fdtable); //disable for rwlock
            pthread_rwlock_wrlock(&table_rwlock);
            tmp2 = fdtable_add();
//            sem_post(&sem_fdtable); //disable for rwlock
            pthread_rwlock_unlock(&table_rwlock);
            tmp2->NetorFile = 0;
            thr_id = pthread_create(&(tmp2->p_thread), NULL, syscall_thread, NULL);
            pthread_detach(tmp2->p_thread);
            tmp2->thr_fd = recv_data_p->return_value;
            if (thr_id < 0) {
                perror("pthread_create error");
            }
            if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
            else errno = func_errno;
            return recv_data_p->return_value;
        }
        else {                                           // when accept() failed
            if(recv_data_p->thr_errno != 0){
                errno = recv_data_p->thr_errno;
            }
            else{
                errno = func_errno;
            }
            return recv_data_p->return_value;
        }
    }
}


int connect(int socket, const struct sockaddr* address, socklen_t address_len)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    struct sockaddr_in *sin = (struct sockaddr_in*)address;

    recv_data_p = &recv_data;
    int func_errno = errno;

    thread_info* tmp;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);

#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_connect)(socket, address, address_len);
    }
    else{
        send_data.request_type = TYPE_CONNECT;
        send_data.connect.socket = socket;
        send_data.connect.address = address;
        send_data.connect.address_len = address_len;

        CPART_send_to_thread(send_data, tmp);

        CPART_recv_from_thread(recv_data_p, tmp);


        if(recv_data_p->thr_errno != 0){
            errno = recv_data_p->thr_errno;
        }
        else{
            errno = func_errno;
        }
        return recv_data.return_value;
    }
}


ssize_t send(int socket, const void* buffer, size_t length, int flags)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;

    thread_info* tmp;
    int func_errno = errno;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL){
        errno = func_errno;
        return (*original_send)(socket, buffer, length, flags);
    }
    else{
        send_data.request_type = TYPE_SEND;
        send_data.send.socket = socket;
        send_data.send.buffer = buffer;
        send_data.send.length = length;
        send_data.send.flags = flags;
        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }

}


ssize_t recv(int socket, void * buf, size_t length, int flags)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_recv)(socket, buf, length, flags);
    }
    else{
        send_data.request_type = TYPE_RECV;
        send_data.recv.socket = socket;
        send_data.recv.buf = buf;
        send_data.recv.length = length;
        send_data.recv.flags = flags;
        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }
}

int setsockopt(int socket, int level, int option_name, const void* option_value, socklen_t option_len)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;
    thread_info* tmp;

    int func_errno = errno;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_setsockopt)(socket, level, option_name, option_value, option_len);
    }
    else{
        send_data.request_type = TYPE_SETSOCKOPT;
        send_data.setsockopt.socket = socket;
        send_data.setsockopt.level = level;
        send_data.setsockopt.option_name = option_name;
        send_data.setsockopt.option_value = option_value;
        send_data.setsockopt.option_len = option_len;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}
int getsockopt(int socket, int level, int option_name, void* buf, socklen_t *addrlen)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL){
        errno = func_errno;
        return (*original_getsockopt)(socket, level, option_name, buf,addrlen);
    }
    else{

        send_data.request_type = TYPE_GETSOCKOPT;
        send_data.getsockopt.socket = socket;
        send_data.getsockopt.level = level;
        send_data.getsockopt.option_name = option_name;
        send_data.getsockopt.buf = buf;
        send_data.getsockopt.addrlen = addrlen;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}


int epoll_create(int size){
    int thr_id;
    int num = 1;
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    int ret;
    int func_errno = errno;
    thread_info *tmp;

    errno = 0;

    ret = (*original_epoll_create)(size);
    if(errno != 0){
        func_errno = errno;
    }
    else{
        errno = func_errno;
    }
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_wrlock(&table_rwlock);

    if( fdtable_get_by_fd_all(ret) != NULL || ret < 0){
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }

    else if(fdtable_getnumber() < MAXTHREAD){
        tmp = fdtable_add();
//        sem_post(&sem_fdtable);                 // disable for fdtable_forked() //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
//        sem_wait(&(tmp->sem_thread));           // tmp disable
        tmp->NetorFile = 0;

        thr_id = pthread_create(&(tmp->p_thread), NULL, syscall_thread, NULL);
        pthread_detach(tmp->p_thread);
        tmp->thr_fd = ret;
        if(thr_id < 0){
            perror("pthread_create error");
        }
    }
    else{
//        sem_post(&sem_fdtable); //disable for rwlock
        pthread_rwlock_unlock(&table_rwlock);
        errno = func_errno;
        return ret;
    }

    errno = func_errno;
    return ret;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *events){
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    thread_info* tmp;
    int func_errno = errno;

//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);

#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(epfd, 0);
#else
    tmp = fdtable_get_by_fd(epfd);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL)
    {
        errno = func_errno;
        return (*original_epoll_ctl)(epfd, op, fd, events);
    }
    else
    {

        send_data.request_type = TYPE_EPOLL_CTL;
        send_data.epoll_ctl.epfd = epfd;
        send_data.epoll_ctl.op = op;
        send_data.epoll_ctl.fd = fd;
        send_data.epoll_ctl.events = events;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);

        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}
int poll(pollfd *ufds, unsigned int nfds, int timeout)
{
    int (*original_poll)(pollfd *ufds, unsigned int nfds, int timeout);
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;

    recv_data_p = &recv_data;

    original_poll = dlsym(RTLD_NEXT, "poll");
    thread_info* tmp;
    int func_errno = errno;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(ufds[nfds-1].fd, 0);
#else
    tmp = fdtable_get_by_fd(ufds[nfds-1].fd);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL)
    {
        errno = func_errno;
        return (*original_poll)(ufds, nfds, timeout);
    }
    else
    {
        send_data.request_type = TYPE_POLL;
        send_data.poll.ufds = ufds;
        send_data.poll.nfds = nfds;
        send_data.poll.timeout = timeout;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}


ssize_t sendto(int socket, const void* buffer, size_t length, int flags, const struct sockaddr *address, socklen_t address_len)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL){
        errno = func_errno;
        return (*original_sendto)(socket, buffer, length, flags, address, address_len);
    }
    else{
        send_data.request_type = TYPE_SENDTO;
        send_data.sendto.socket = socket;
        send_data.sendto.buffer = buffer;
        send_data.sendto.length = length;
        send_data.sendto.flags = flags;
        send_data.sendto.address = address;
        send_data.sendto.address_len = address_len;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }
}

ssize_t sendmsg(int socket, const struct msghdr *msg, int flags)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);

    if(tmp == NULL){
        errno = 0;
        return (*original_sendmsg)(socket, msg, flags);
    }
    else{
        send_data.request_type = TYPE_SENDMSG;
        send_data.sendmsg.socket = socket;
        send_data.sendmsg.msg = msg;
        send_data.sendmsg.flags = flags;

        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }
}

ssize_t recvfrom(int socket, void * buf, size_t length, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    int func_errno = errno;

    thread_info* tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
//	printf("recvfrom buf :: %s \n =============================", (char*)buf);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_recvfrom)(socket, buf, length, flags, addr, addrlen);
    }
    else{
        send_data.request_type = TYPE_RECVFROM;
        send_data.recvfrom.socket = socket;
        send_data.recvfrom.buf = buf;
        send_data.recvfrom.length = length;
        send_data.recvfrom.flags = flags;
        send_data.recvfrom.addr = addr;
        send_data.recvfrom.addrlen = addrlen;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }
}

ssize_t recvmsg(int socket, struct msghdr *msg_rcv, int flags)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info *tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_recvmsg)(socket, msg_rcv, flags);
    }
    else{
        send_data.request_type = TYPE_RECVMSG;
        send_data.recvmsg.socket = socket;
        send_data.recvmsg.msg_rcv = msg_rcv;
        send_data.recvmsg.flags = flags;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);

        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_size;
    }
}

int getsockname(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp ;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL)
    {
        errno = func_errno;
        return (*original_getsockname)(socket, addr, addrlen);
    }
    else{
        send_data.request_type = TYPE_GETSOCKNAME;
        send_data.getsockname.socket = socket;
        send_data.getsockname.addr = addr;
        send_data.getsockname.addrlen = addrlen;


        CPART_send_to_thread(send_data, tmp);
        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}

int getpeername(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;

    int func_errno = errno;

    thread_info* tmp;
//    sem_wait(&sem_fdtable); //disable for rwlock
    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd(socket, 0);
#else
    tmp = fdtable_get_by_fd(socket);
#endif
//    sem_post(&sem_fdtable); //disable for rwlock
    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_getpeername)(socket, addr, addrlen);
    }
    else{
        send_data.request_type = TYPE_GETPEERNAME;
        send_data.getpeername.socket = socket;
        send_data.getpeername.addr = addr;
        send_data.getpeername.addrlen = addrlen;


        CPART_send_to_thread(send_data, tmp);

        CPART_recv_from_thread(recv_data_p, tmp);
        if(recv_data_p->thr_errno != 0) errno = recv_data_p->thr_errno;
        else errno = func_errno;
        return recv_data.return_value;
    }
}


int shutdown(int socket, int flags)
{
    int ret_flag;
    int ret; //
    thread_info* tmp;
    args_data send_data = {1, 0};
    retval_data recv_data = {1, 0, 0};
    retval_data* recv_data_p;
    recv_data_p = &recv_data;
    int func_errno = errno;

    pthread_rwlock_rdlock(&table_rwlock);
#ifdef __FILEIO__
    tmp = fdtable_get_by_fd_all(socket);
#else
    tmp = fdtable_get_by_fd(socket);
#endif

    pthread_rwlock_unlock(&table_rwlock);
    if(tmp == NULL){
        errno = func_errno;
        return (*original_shutdown)(socket, flags);
    }
    else{
        pthread_rwlock_wrlock(&table_rwlock);
        //fdtable_entry_delete(socket);
        ret_flag = fdtable_to_pool(socket);
        if(ret_flag == 1){
            thread_info *next_node = tmp->next;
            thread_info *prev_node = tmp->prev;

            prev_node->next = next_node;
            next_node->prev = prev_node;

            sem_destroy(&(tmp->sem_thread));
            sem_destroy(&(tmp->empty));
            sem_destroy(&(tmp->empty2));
            sem_destroy(&(tmp->full));
            sem_destroy(&(tmp->full2));
            memset(tmp->message, 0, sizeof(args_data));      // memset - cglee
            free(tmp->message);
            //pthread_kill(tmp->p_thread, SIGTERM);
            memset(tmp, 0, sizeof(args_data));              // memset - cglee
            free(tmp);

            ret = (*original_shutdown)(socket, flags);

            thr_num--;
            pthread_rwlock_unlock(&table_rwlock);

            return ret;
        }

        pthread_rwlock_unlock(&table_rwlock);

        return (*original_shutdown)(socket, flags);
    }
}




int clone(int (*fn)(void *arg), void *child_stack, int flags, void* arg, ...)
{
    int return_pid_t;
    int (*original_clone)(int (*fn)(void *arg), void* child_stack, int flags, void* arg);

    pool_thr_num = pool_thr_num*2;
    thr_num = thr_num*2;

    original_clone = dlsym(RTLD_NEXT, "clone");

    return_pid_t = (*original_clone)(fn, child_stack, flags, arg);

    switch(return_pid_t){
        case 0:
            fdtable_init();
            fdtable_init_pool();
            pthread_rwlock_init(&table_rwlock, NULL);
            break;
        case -1:
            perror("error fork\n");
            break;
        default:
            break;
    }

    return return_pid_t;
}


pid_t fork()
{
    pool_thr_num = pool_thr_num*2;
    thr_num = thr_num*2;
    pid_t return_pid_t;

    return_pid_t = (*original_fork)();

    switch(return_pid_t){
        case 0:
            fdtable_init();
            fdtable_init_pool();
            pthread_rwlock_init(&table_rwlock, NULL);
//            fdtable_forked(syscall_thread, ku_select);
            break;
        case -1:
            perror("error fork\n");
            break;
        default:
            break;
    }
    return return_pid_t;
}
