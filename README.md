# Sycalib


## License

GNU General Public License version 2 (GPLv2)


## Introduction

 As the number of cores equipped in a computing node increases, it is more expected that a large number of cores can elevate not only scalability of computation but performance of network I/O. However, scalability issue on many-core processor systems has been constantly raised. Sharing common data structures between cores causes high locking and cache coherency overheads which are the main factors in scalability degradation. Entering kernel mode is required when network I/O is performed by invoking network I / O related system calls. However, if context switching occurs on the same core, it causes cache pollution and TLB (Traslation Lookaside Buffer) contamination. Many studies have been conducted to improve scalability and network I/O performance on many-core systems through modifying system software, operating system, or providing additional API layer which requires application modification. We propose sycalib that can improve network I/O performance and scalability through assigning network I/O tasks to optimal cores using core affinity without modifying existing programs.

## What is Sycalib

This repository contains the library called sycalib that dynamically decides the core affinity of system calls. sycalib aims to enhance the network I/O performance on many-core systems while providing application transparency. Main features of sycalib can be summarized as follows:

- sycalib overrides the legacy system call library and hooks the network I/O system calls
- The system call context is separate from application contexts
- The core affinity of the system call contexts is dynamically decided by considering current loads, cache layout, and I/O bus.
- sycalib does not require any modifications of existing applications and the Linux kernel

### Single-socket Core Partitioning

Limits cores that execute block and network I/O system calls to the NUMA node closest to the relevant I/O devices.

<img src="https://github.com/oslab-swrc/syscalib/blob/master/single.png"  width="600" height="300"/>

### Cross-socket Core Partitioning

Is similar to the Single-NUMA-node policy but allows system calls to utilize a NUMA node other than the one closest to the I/O devices if its utilization is higher than the threshold.

<img src="https://github.com/oslab-swrc/syscalib/blob/master/cross.png"  width="600" height="300"/>

### Per-socket core partitioning

Assigns I/O system calls to cores belonging to the NUMA node where the corresponding application is running.

Considers the locality of data buffers importantly and potentially allows more core utilization for system call contexts than the Single-NUMA-node policy.

<img src="https://github.com/oslab-swrc/syscalib/blob/master/per.png"  width="600" height="300"/>

## How to run

- Build core partitioning kernel module(simple_proc.ko) and shared library(CPART_SINGLE.so, CPART_CROSS.so, CPART_PER.so) using Makefile and build.sh script.
~~~
 $ sh build.sh
~~~
- Insert a kernel module.
~~~
 $ sudo insmod {simple_proc_PATH}/simple_proc.ko irq_net={NET_QUEUES} irq_blk={BLK_QUEUES}
~~~
  - Parameters
    - irq_net : network device irq numbers
    - irq_blk : block device irq numbers
- If you use the syscalib for global system
  - LD_PRELOAD the shared library in .bashrc file
- If you use the syscalib for application
  - LD_PRELOAD the shared library when you the run application
~~~
 $ LD_PRELOAD={COREPARTITIONING_PATH}/CPART_{SINGLE|CROSS|PER} ./{your application}
~~~

## Results
/proc/KU/dynamic has your corepartitioning informantion
~~~
 $ cat /proc/KU/dynamic
~~~

                                                                                                     
## requirement list
Core partitioning currently supports many system calls used for network and file I/O.
If there are additional system calls used for I/O, they need to be added.
Of course, the added system call must follow the existing operating context of Linux, and must be operated through the syscall thread of core partitioning.


Below are the system calls currently supported by core partitioning.
---
*select(), socket(), bind(), listen(), accept(), connect(), send(), recv(), setsocketopt(), getsocketopt(), close(), read(), write(), poll(), ppoll(), sendto(), sendmsg(), recvmsg(), recvfrom(), getsockname(), getpeername(), shutdown(), epoll_wait(), epoll_ctl(), epoll_create(), socketpari(), open(), openat(), open64(), openat64(), creat(), lseek(), stat(), lseek64(), stat64(), fopen(), fork(), clone()* 
---


## Papers

[공유메모리를 통한 향상된 메시지 기반 시스템 호출](https://www.dbpia.co.kr/Journal/articleDetail?nodeId=NODE07322648)

[Application-transparent Scheduling of Socket System Calls on Many-core Systems](https://dl.acm.org/doi/10.1145/3230718.3232113)

[매니코어 환경에서 시스템 호출과 고성능 입출력 장치를 위한 동적 코어 친화도](https://www.dbpia.co.kr/Journal/articleDetail?nodeId=NODE09301835)

[Transparent Many-core Partitioning for High-performance Big Data I/O](https://onlinelibrary.wiley.com/doi/10.1002/cpe.6017)

[매니코어 파티셔닝을 위한 동적 코어 친화도](https://www.dbpia.co.kr/Journal/articleDetail?nodeId=NODE10501401)

[NUMA-aware I/O System Call Steering](https://www.computer.org/csdl/proceedings-article/cluster/2021/966600a805/1xFuXRrI520)

