#include <bpf/libbpf_legacy.h>
#include <stdio.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "uptime.skel.h"

int handle_event(void *ctx, void *_event, unsigned long _event_size) {
    struct event *event = _event;

    double uptime_ms = (double)(event->uptime) / 1e6;

    printf("process [%d](%s) was alive for %lf milliseconds\n", event->pid,
           event->comm, uptime_ms);

    return 0;
}

int main() {
    struct uptime_bpf *skel;
    skel = uptime_bpf__open_and_load();

    if (!skel) {
        printf("error opening or loading the skeleton\n");
        return 1;
    }

    if (uptime_bpf__attach(skel) < 0) {
        printf("error attaching\n");
        uptime_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *ring;
    ring = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL,
                            NULL);

    if (!ring) {
        printf("error creating ring buffer\n");
        uptime_bpf__destroy(skel);
        return 1;
    }

    printf("polling for events...\n");

    while (1) {
        ring_buffer__poll(ring, -1);
    }

    return 0;
}
