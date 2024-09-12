//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct test_msg {
	int  send;
	char file[256];
	int algo;
	char hash[64];
};

struct ima_hash {
	int algo;
	char hash[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcpmon_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct test_msg);
} process_call_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct ima_hash);
} ima_hash_map SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(init_bprm_check, struct linux_binprm *bprm)
{
	int zero = 0;
	struct test_msg *event;
	struct ima_hash hash;
	__builtin_memset(&hash, 0, sizeof(struct ima_hash));

	event = bpf_map_lookup_elem(&process_call_heap, &zero);
	if (!event)
		return 0;
	bpf_probe_read_kernel_str(&event->file, sizeof(event->file), bprm->filename);
	if (event->file[0] == '.' && event->file[1] == '/') {
		// emulate filter
		event->send = 1;
		// Put dummy entry in the map if element is in map, than we need to calculate hash
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&ima_hash_map, &pid_tgid, &hash, BPF_ANY);
	} else {
		event->send = 0;
	}
	return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(ima_bprm_check, struct linux_binprm *bprm)
{
	// Maybe put dummy entry at init prog phase
	struct ima_hash hash;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ima_hash *need_calc = bpf_map_lookup_elem(&ima_hash_map, &pid_tgid);
	if (need_calc) {
		__builtin_memset(&hash, 0, sizeof(struct ima_hash));
		hash.algo = bpf_ima_inode_hash(bprm->file->f_inode, &hash.hash, 64);
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&ima_hash_map, &pid_tgid, &hash, BPF_ANY);
	}
	return 0;
}
SEC("lsm/bprm_check_security")
int BPF_PROG(send_bprm_check, struct linux_binprm *bprm)
{
	int zero = 0;
	struct test_msg *event;
	event = bpf_map_lookup_elem(&process_call_heap, &zero);
	if (!event)
		return 0;
	if (event->send == 1) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		struct ima_hash *hash = bpf_map_lookup_elem(&ima_hash_map, &pid_tgid);
		if (hash) {
			event->algo = hash->algo;
			bpf_probe_read(&event->hash, 64, &hash->hash);
			bpf_map_delete_elem(&ima_hash_map, &pid_tgid);
		}
		bpf_perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, sizeof(struct test_msg));
	}
	return 0;
}

char __license[] SEC("license") = "GPL";
