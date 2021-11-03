# build 3-way core partitioning library
gcc -pthread -Wall -fPIC -shared -Wl,--no-as-needed -ldl -o CPART_SINGLE.so fdtable.c ipc.c ld_preload.c print.c affinity.c -D__FILEIO__ -DSINGLE
gcc -pthread -Wall -fPIC -shared -Wl,--no-as-needed -ldl -o CPART_CROSS.so fdtable.c ipc.c ld_preload.c print.c affinity.c -D__FILEIO__ -DCROSS
gcc -pthread -Wall -fPIC -shared -Wl,--no-as-needed -ldl -o CPART_PER.so fdtable.c ipc.c ld_preload.c print.c affinity.c -D__FILEIO__ -DPER


