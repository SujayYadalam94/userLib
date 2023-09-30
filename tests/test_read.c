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
#include <pthread.h>

#define NUM_THREADS 1
#define PAGE_ALIGN(len)   ((len+4095)&(~(typeof(len))4095))

const char *files[4]={"/mnt/nvme/sample.csv",
                      "/mnt/nvme/sample2.csv",
                      "/mnt/nvme/sample3.csv",
                      "/mnt/nvme/sample4.csv"};

int size = 0 ;
pthread_barrier_t barrier;

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("lfence");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void* readFunc(void *arg) {
    int fd1;
    int fd2;
    int ret;
    char *dummy, *buf;
    uint64_t start, end;
    struct timespec stime, etime;
    double avg = 0;
    int count = 0;

    char str[16];

    sprintf(str, "out%d", gettid());

    //fd2 = open(str, O_RDWR | O_CREAT, 0666);

    printf("Opening %s\n", (char*)arg);
    fd1 = open(arg, O_RDONLY | O_DIRECT);
    if (fd1 < 0) {
        printf("Error opening file\n");
        return NULL;
    }

    pthread_barrier_wait(&barrier);

    //dummy = malloc(20 * 1024 * 1024UL);
    //memset(dummy, '0', 20 * 1024 * 1024UL);
    posix_memalign((void **)&buf, 4096, PAGE_ALIGN(size));
    ret = 1;
    while(ret > 0) {
        //start = rdtsc();
        clock_gettime(CLOCK_REALTIME, &stime);
        ret = read(fd1, buf, size);
        clock_gettime(CLOCK_REALTIME, &etime);
        //end = rdtsc();
        //avg += end - start;
        avg += (etime.tv_sec - stime.tv_sec) * 1e6 + (etime.tv_nsec - stime.tv_nsec) / 1e3;
        count++;
        //for (int i=0;i<ret;++i) printf("%c", buf[i]);
        //write(fd2, buf, ret);
    }
    avg /= count;
    //avg /= 2893.36;
    printf("Time: %f, count=%d\n", (double)(avg), count);

    free(buf);

    close(fd1);
    //close(fd2);
}

int main(int argc, char* argv[]) {
    int ret;
    pthread_t tid[NUM_THREADS];

    size = atoi(argv[1]);

    pthread_barrier_init(&barrier,NULL,NUM_THREADS);

    for (int i=0; i<NUM_THREADS; ++i) {
        ret = pthread_create(&tid[i], NULL, (void * (*)(void*)) &readFunc, files[i]);
        if (ret != 0)
            printf("pthread failed\n");
    }

    for (int i=0; i<NUM_THREADS; ++i) {
        pthread_join(tid[i], NULL);
    }

    return 0;
}
