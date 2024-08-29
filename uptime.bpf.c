#include <linux/bpf.h>
#include <stdint.h>
#include <unistd.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, uint64_t);
    __uint(max_entries, 4096);
} processes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 4096);
} ringbuf SEC(".maps");

__attribute__((always_inline)) pid_t current_pid() {
    return bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
    pid_t pid = current_pid();

    uint64_t timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&processes, &pid, &timestamp, BPF_ANY);

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    pid_t pid = current_pid();

    uint64_t *time = bpf_map_lookup_elem(&processes, &pid);

    if (!time) {
        return 0;
    }

    struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);

    if (!event) {
        return 0;
    }

    uint64_t curr_time = bpf_ktime_get_ns();

    uint64_t uptime = curr_time - *time;

    if (bpf_map_delete_elem(&processes, &pid) < 0) {
        bpf_printk("error deleting from map\n");
    }

    event->pid = pid;
    event->uptime = uptime;

    if (bpf_get_current_comm(&event->comm, COMM_MAX_SIZE) < 0) {
        bpf_printk("error getting comm\n");
    }

    bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
