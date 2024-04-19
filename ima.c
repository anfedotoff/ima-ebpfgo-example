//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    unsigned char hook;
    char file[256];
    unsigned char algo;
    char hash[64];

};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	 __uint(max_entries, 64 * 4096);
} rb SEC(".maps");

SEC("lsm.s/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    struct event *event = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!event) {
        return 1;
    }
    bpf_probe_read_kernel_str(event->file, sizeof(event->file), bprm->filename); //TODO: absolute path
    event->algo = bpf_ima_inode_hash(bprm->file->f_inode, &event->hash, 64);
    event->hook = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file)
{
    struct event *event = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!event) {
        return 1;
    }
    bpf_probe_read_kernel_str(event->file, sizeof(event->file), file->f_path.dentry->d_name.name); //TODO: absolute path
    event->algo = bpf_ima_inode_hash(file->f_inode, &event->hash, 64);
    event->hook = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
