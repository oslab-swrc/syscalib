# Sycalib
## Introduction
 As the number of cores equipped in a computing node increases, it is more expected that a large number of cores can elevate not only scalability of computation but performance of network I/O. However, scalability issue on many-core processor systems has been constantly raised. Sharing common data structures between cores causes high locking and cache coherency overheads which are the main factors in scalability degradation. Entering kernel mode is required to invoke network I/O related system calls to perform network I/O. However, if context switching is performed on the same core, it causes cache pollution and TLB(Traslation Lookaside Buffer) pollution. Many studies has been conducted to improve scalability and network I/O performance on many-core systems through modifying system software, operating system, or providing additional API layer which requires application modification. We suggest sycalib that can improve network I/O performance and scalability through assigns network I/O tasks to optimal cores using core affinity without modifying existing programs.

## What is Sycalib 
This repository contains the library called sycalib that dynamically decides the core affinity of system calls. sycalib aims to enhance the network I/O performance on many-core systems while providing application transparency. Main features of sycalib can be summarized as follows:

- sycalib overrides the legacy system call library and hooks the network I/O system calls
- The system call context is separate from application contexts
- The core affinity of the system call contexts is dynamically decided by considering current loads, cache layout, and I/O bus.
- sycalib does not require any modifications of existing applications and the Linux kernel.

## Getting Started
We plan to release the first version of sycalib in early 2018.
