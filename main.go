package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type bpfEvent struct {
	Hook byte
	File [256]byte
	Algo byte
	Hash [64]byte
}

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs imaObjects
	if err := loadImaObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	execHook, err := link.AttachLSM(link.LSMOptions{Program: objs.imaPrograms.FileOpen})
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer execHook.Close()

	fopenHook, err := link.AttachLSM(link.LSMOptions{Program: objs.imaPrograms.BprmCheckSecurity})
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer fopenHook.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		var hashSize int
		var hashAlgo string
		switch event.Algo {
		// TODO: support more algorithms
		case 2:
			hashSize = 20
			hashAlgo = "SHA1"
		case 4: // SHA256
			hashSize = 64
			hashAlgo = "SHA256"
		default: // Case for errors
			continue

		}
		hook := "Execve"
		if event.Hook == 1 {
			hook = "FileOpen"
		}
		fname := string(event.File[:bytes.Index(event.File[:], []byte{0})])
		log.Printf("<%s>\n", hook)
		log.Printf("File: %s\n", fname)
		log.Printf("%s: %s\n", hashAlgo, hex.EncodeToString(event.Hash[:hashSize]))
		if event.Hook == 0 {
			// Get security.ima for exec event (fname should be abs path)
			sz, err := unix.Getxattr(fname, "security.ima", nil)
			if err == nil && sz != 0 {
				ima := make([]byte, sz)
				unix.Getxattr(fname, "security.ima", ima)
				offset := 0
				if event.Algo <= 2 {
					offset = 1
				}
				log.Printf("security.ima: %v\n", hex.EncodeToString(ima[offset:]))
				// Compare
				if bytes.Equal(event.Hash[:hashSize], ima[offset:]) {
					log.Printf("Integrity check: OK")
				} else {

					log.Printf("Integrity check: FAIL")
				}
			}
		}
		log.Printf("<=============>\n")
	}
}
