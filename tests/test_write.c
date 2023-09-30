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

#define WRITE_SIZE atoi(argv[1])
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
    posix_memalign((void **)&buf, 4096, PAGE_ALIGN(WRITE_SIZE));
    uint64_t start,end;
    double avg = 0;
    int count = 0;

    if (argc < 4) {
        printf("Usage: ./test_write.x size count char\n");
        return 1;
    }

    fd1 = open("/mnt/nvme/writefile.txt", O_RDWR | O_CREAT | O_DIRECT, 0666);
    if (fd1 < 0) {
        printf("Error opening file\n");
        free(buf);
        return 1;
    }

    memset(buf, argv[3][0], WRITE_SIZE);
    ret = 1;
    while(count < atoi(argv[2])) {
        start = rdtsc();
        ret = write(fd1, buf, WRITE_SIZE);
        end = rdtsc();
        avg += end - start;
        count++;
    }
    avg /= count;
    avg /= 2893.36;
    printf("Time: %f, count=%d\n", (double)(avg), count);

    free(buf);

    close(fd1);
    return 0;
}
