# Sycalib
This repository contains the library called sycalib that dynamically decides the core affinity of system calls. CAIOS aims to enhance the network I/O performance on many-core systems while providing application transparency. Main features of CAIOS can be summarized as follows:

- sycalib overrides the legacy system call library and hooks the network I/O system calls
- The system call context is separate from application contexts
- The core affinity of the system call contexts is dynamically decided by considering current loads, cache layout, and I/O bus.
- sycalib does not require any modifications of existing applications and the Linux kernel.

We plan to release the first version of sycalib in early 2018.
