# FIM example based on IMA and LSM BPF

This example shows how to collect IMA-measured hashes of executed binaries and
opened files with LSM BPF hooks.

## Quick start

Enable IMA and LSM:
Add `rootflags=i_version lsm=integrity,bpf ima_policy=tcb` to
`GRUB_CMDLINE_LINUX` in `/etc/default/grub`. Update grub and reboot.

Install ebpf-go [dependencies](https://ebpf-go.dev/guides/getting-started/#ebpf-c-program)

```
go mod init ima-test && go mod tidy
go get github.com/cilium/ebpf/cmd/bpf2go
```

Get vmlinux.h:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Run go generate and build:

```
go generate && go build
```
Run example:

```
sudo ./ima-test
```
