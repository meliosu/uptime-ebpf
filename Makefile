all: uptime

uptime: uptime.skel.h
	clang -O2 -g -o uptime uptime.c -lbpf

uptime.skel.h: uptime.bpf.o
	bpftool gen skeleton uptime.bpf.o > uptime.skel.h

uptime.bpf.o:
	clang -O2 -g -target bpf -c uptime.bpf.c


clean:
	rm uptime uptime.skel.h uptime.bpf.o
