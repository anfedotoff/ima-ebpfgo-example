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
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfEvent struct {
	Send int32
	File [256]byte
	Algo int32
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

	sendBprmHook, err := link.AttachLSM(link.LSMOptions{Program: objs.imaPrograms.SendBprmCheck})
	if err != nil {
		log.Fatalf("linking LSM failed: %s", err)
	}
	defer sendBprmHook.Close()
	imaBprmHook, err := link.AttachLSM(link.LSMOptions{Program: objs.imaPrograms.ImaBprmCheck})
	if err != nil {
		log.Fatalf("linking LSM failed: %s", err)
	}
	defer imaBprmHook.Close()

	initBprmHook, err := link.AttachLSM(link.LSMOptions{Program: objs.imaPrograms.InitBprmCheck})
	if err != nil {
		log.Fatalf("linking LSM failed: %s", err)
	}
	defer initBprmHook.Close()

	rd, err := perf.NewReader(objs.TcpmonMap, 65535)
	if err != nil {
		log.Fatalf("opening perf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

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
			log.Printf("parsing perf event: %s", err)
			continue
		}
		var hashSize int
		var hashAlgo string
		fname := string(event.File[:bytes.Index(event.File[:], []byte{0})])
		switch event.Algo {
		case 2:
			hashSize = 20
			hashAlgo = "SHA1"
		case 4: // SHA256
			hashSize = 64
			hashAlgo = "SHA256"
		default: // Case for errors
			log.Printf("Error file: %s. Code:%d\n", fname, event.Algo)
			continue

		}
		log.Printf("File: %s\n", fname)
		log.Printf("%s: %s\n", hashAlgo, hex.EncodeToString(event.Hash[:hashSize]))
		log.Printf("<=============>\n")
	}
}
