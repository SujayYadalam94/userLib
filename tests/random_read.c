#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/time.h>

#define READ_SIZE atoi(argv[1])
#define PAGE_ALIGN(len)   ((len+4095)&(~(typeof(len))4095))

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("lfence");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(int argc, char* argv[]) {
    int fd1, fd2;
    int ret;
    char *buf;
    posix_memalign((void **)&buf, 4096, PAGE_ALIGN(READ_SIZE));
    uint64_t start,end;
    double avg = 0;
    int count = 0;
    int idx;

    srand(time(NULL));

    fd1 = open("/mnt/nvme/sample.csv", O_RDONLY | O_DIRECT);
    if (fd1 < 0) {
        printf("Error opening file\n");
        free(buf);
        return 1;
    }
    
    ret = 1;
    while(count < 100000) {
        idx = rand() % 16384; 
        start = rdtsc();
        ret = pread64(fd1, buf, READ_SIZE, idx*4096);
        end = rdtsc();
        avg += end - start;
        count++;
        //for(int i=0;i<ret;++i)
        //    printf("%c", buf[i]);
    }
    if (count > 1)
	count--;
    avg /= count;
    avg /= 2200;
    printf("Time: %f, count=%d\n", (double)(avg), count);

    fd2 = open("/mnt/nvme/sample.txt", O_RDONLY | O_DIRECT);
    if (fd2 < 0) {
        printf("Error opening file\n");
        free(buf);
        return 1;
    }
    
    ret = 1;
    count = 0;
    avg = 0;
    while(ret > 0) {
        start = rdtsc();
        ret = read(fd2, buf, READ_SIZE);
        end = rdtsc();
        avg += end - start;
        count++;
        //for(int i=0;i<ret;++i)
        //   printf("%c", buf[i]);
    }
    if (count > 1)
	count--;
    avg /= count;
    avg /= 2200;
    printf("Time: %f, count=%d\n", (double)(avg), count);

    free(buf);

    close(fd1);
    close(fd2);
    return 0;
}
