#include <stdint.h>
#include <unistd.h>

#define COMM_MAX_SIZE 256

struct event {
    pid_t pid;
    uint64_t uptime;
    char comm[COMM_MAX_SIZE];
};
