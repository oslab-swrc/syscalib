/*SPDX-License-Identifier: GPL-2.0- WITH Linux-syscall-note*/
/*Copyright (c) 2021 Konkuk University SSLAB*/

#include "ld_preload.h"

int get_app_cpu(){
	FILE* fp;
	char proc_tmp[256];
	char stat[1024];
	char *token;
	int i = 0;
	int cpu = -1;
	sprintf(proc_tmp,"/proc/%d/stat",getpid());
	fp = fopen(proc_tmp, "r");
	if(fp == NULL){
		printf("file open error \n");
	}else{
		fgets(stat, 1024, fp);
		token = strtok(stat," ");
		while(token != NULL){
			token = strtok(NULL," ");
			if(i == 38) break;
			i++;
		}
	}
	cpu = atoi(token);
	fclose(fp); 		// add fclose(fp) - cglee
	return cpu;
}

int set_affinity_within(boolean NetorFile){
/*read which cpu core application is running on and set syscall affinity in same socket*/
	int app_cpu = get_app_cpu();
	int syscall_cpu = 0;
	if(app_cpu < ONE_NODE){
		set_cpu(0, NetorFile);
	}else {
		set_cpu(1, NetorFile);
	}
	return syscall_cpu ;
}

void set_cpu(boolean socket, boolean NetorFile)
{
	int n=0, i=0 ;
	int k=0;
	int sum_user=0, sum_syscall=0, sum_intr=0;
	int sum_total = 0;
	int minimum = 0;

	char total_filepath[PROC_MAX_LEN], total_buf[INTEL_CPU][PROC_MAX_LEN];  //changyu-lee : total_buf[PROC_MAX_LEN][INTEL_CPU] -> [INTEL_CPU][PROC_MAX_LEN]
    char dynamic_filepath[PROC_MAX_LEN], dynamic_buf[INTEL_CPU][PROC_MAX_LEN];
    char core_start_end[2][10];        // 0 for net 1 for blk
    char core_start_end_per[16][10];
	FILE *ft = NULL ;
    FILE *dynamic = NULL ;

	n = sprintf(total_filepath, "/proc/KU/total");
    k = sprintf(dynamic_filepath, "/proc/KU/dynamic");

	ft = fopen(total_filepath, "r");
    dynamic = fopen(dynamic_filepath, "r");

	if(!ft || !dynamic){
		printf("total fopen failed \n");
	}
    for(int counter = 0 ; counter < INTEL_CPU ; counter++){
        fgets(total_buf[counter], PROC_MAX_LEN-1, ft);
    }
#ifdef SINGLE
    fgets(core_start_end[0], 9, dynamic);
    fgets(core_start_end[1], 9, dynamic);
    net_end = atoi(core_start_end[0]);
    file_start = atoi(core_start_end[1]);

#endif

#ifdef CROSS
    fgets(sockets_count[0], 9, dynamic);   //blk
    fgets(sockets_count[1], 9, dynamic);   //net

    int m = 0;
    k = 0;
    for(m = 0 ; m < 16 ; m++){
        fgets(core_start_end_per[m], 9, dynamic);
        if(m%2 == 0){
            net_end_per[k] = atoi(core_start_end_per[m]);
        }
        else{
            blk_start_per[k] = atoi(core_start_end_per[m]);
            k++;
        }
    }
#endif

#ifdef PER
    int m = 0;
    k = 0;
    for(m = 0 ; m < 16 ; m++){
        fgets(core_start_end_per[m], 9, dynamic);
        if(m%2 == 0){
            net_end_per[k] = atoi(core_start_end_per[m]);
        }
        else{
            blk_start_per[k] = atoi(core_start_end_per[m]);
            k++;
        }
    }
#endif
    fclose(ft);
    fclose(dynamic);

#ifdef __FILEIO__
#ifdef SINGLE
    if(NetorFile == 0){ /* NetIO */
		minimum = net_end+1;

		CPU_ZERO(&mask);
		for(net_cpu = net_end+1; net_cpu < CORES_PER_SOCKET; net_cpu++){
			CPU_SET(net_cpu, &mask);
		}

		//CPU_SET(net_cpu, &mask);
		sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	}
	else{/* FileIO*/
		minimum = file_start;

		CPU_ZERO(&mask);
		for(file_cpu = file_start; file_cpu < 192; file_cpu++){
			CPU_SET(file_cpu, &mask);
		}

		//CPU_SET(file_cpu, &mask);
		sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	}
#endif

#ifdef CROSS
	//int current_core = sched_getaffinity(0, sizeof(cpu_set_t), &mask);
	int current_core = sched_getcpu();
	int current_node;
	int socketcount = 0;
	current_node = current_core/15;
    if(NetorFile == 0){ /* NetIO */
            minimum = net_end_per[0]+1;

            CPU_ZERO(&mask);
            for(i = 0 ; i < sockets_count[1]; i++){
                for(k = net_end_per[i] ; k < (i*23)+23 ; k++){
                    CPU_SET(k, &mask);
                }
            }

            sched_setaffinity(0, sizeof(cpu_set_t), &mask);
        }
        else{/* FileIO*/
            minimum = blk_start_per[current_node];

            CPU_ZERO(&mask);
            for(i = 0 ; i < sockets_count[0]; i++){
                for(k = blk_start_per[7-i] ; k < (i*23)+23 ; k++){
                    CPU_SET(k, &mask);
                }
            }
            //CPU_SET(file_cpu, &mask);
            sched_setaffinity(0, sizeof(cpu_set_t), &mask);
        }
#endif

#ifdef PER
	int current_core = sched_getcpu();
	int current_node;
	current_node = current_core/NUMBER_OF_SOCKET;
    if(NetorFile == 0){ /* NetIO */
            minimum = net_end_per[current_node]+1;

            CPU_ZERO(&mask);
            for(net_cpu = net_end_per[current_node]+1; net_cpu < blk_start_per[current_node]; net_cpu++){
                CPU_SET(net_cpu, &mask);
            }
            sched_setaffinity(0, sizeof(cpu_set_t), &mask);
        }
        else{/* FileIO*/
            minimum = blk_start_per[current_node];

            CPU_ZERO(&mask);
            for(file_cpu = blk_start_per[current_node]; file_cpu < ((current_node*CORES_PER_SOCKET)+CORES_PER_SOCKET-1); file_cpu++){
                CPU_SET(file_cpu, &mask);
            }
            //CPU_SET(file_cpu, &mask);
            sched_setaffinity(0, sizeof(cpu_set_t), &mask);
        }
#endif


#endif
#ifndef __FILEIO__
	/* for konkuk server cross core partitioning
	if(socket == 0){ //processor socket 0 
		if(atoi(total_buf[socket0_cpu]) > THRESHOLD){
			if(socket0_cpu <= 10 && socket0_cpu > 0) socket0_cpu ++;
			else socket0_cpu = 3;
		}
		CPU_ZERO(&mask);
		CPU_SET(socket0_cpu, &mask);
		sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	}
	else{//processor socket 1 
		if(atoi(total_buf[socket1_cpu]) > THRESHOLD){
			if(socket1_cpu <= 20 && socket1_cpu > 10 ) socket1_cpu++;
			else socket1_cpu = 11;
		}
		CPU_ZERO(&mask);
		CPU_SET(socket1_cpu, &mask);
		sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	}
	*/
#endif

}
