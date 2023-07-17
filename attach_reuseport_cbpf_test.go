// Copyright 2023 Dominik Zeromski <dzeromsk@gmail.com>

// Test functionality of BPF filters with SO_REUSEPORT.
//
// This test creates an SO_REUSEPORT receiver group containing one socket
// per CPU core.
//
// It then creates a BPF program that will select a socket from this group
// based on the core id that receives the packet.
//
// The sending code artificially moves itself to run on different core ids
// and sends one message from each core. Since these packets are delivered
// over loopback, they should  arrive on the same core that sent them.
//
// The receiving code then ensures that the packet was received on the
// socket for the corresponding core id.
package golangsoreuseport

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

var rawSMPProcessorID = SKF_AD_OFF + SKF_AD_CPU

var code = [...]unix.SockFilter{
	{unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, 0, 0, uint32(rawSMPProcessorID)}, // A = raw_smp_processor_id()
	{unix.BPF_RET | unix.BPF_A, 0, 0, 0},                                       // return A
}

var prog = unix.SockFprog{
	Len:    uint16(len(code)),
	Filter: &code[0],
}

var address = flag.String("address", "127.0.0.1:16422", "Address used by test")

func TestListenerProcess(t *testing.T) {
	cpu := os.Getenv("TEST_LISTENER_PROCESS_CPUID")
	if cpu == "" {
		t.Skip()
	}
	defer os.Exit(0)

	t.Log("Subprocess running", cpu)
	runtime.GOMAXPROCS(1)

	p := os.NewFile(uintptr(3), "pipe")
	defer p.WriteString(cpu)

	// setup affinity
	cpuid, err := strconv.Atoi(cpu)
	if err != nil {
		t.Fatal(err)
	}
	var cpuset unix.CPUSet
	cpuset.Set(cpuid)
	err = unix.SchedSetaffinity(0, &cpuset)
	if err != nil {
		t.Fatal(err)
	}

	// listener setup
	lc := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var err error
			err2 := raw.Control(func(fd uintptr) {
				// enable SO_REUSEPORT
				t.Log("Setting SO_REUSEPORT", fd, cpuid)
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if err != nil {
					return
				}

				// only one socket can setup cbpf
				if cpuid != 0 {
					return
				}

				// enable SO_ATTACH_REUSEPORT_CBPF
				err = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, &prog)
				if err != nil {
					return
				}
			})
			if err2 != nil {
				return err2
			}
			return err
		},
	}

	ctx := context.Background()
	ln, err := lc.Listen(ctx, "tcp", *address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// inform parent that we are ready
	_, err = p.Write([]byte(cpu))
	if err != nil {
		t.Fatal(err)
	}

	// respond with cpuid to every client
	for {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.WriteString(c, cpu)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}

func TestListenerWithReuseport(t *testing.T) {
	runtime.GOMAXPROCS(1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// start separate process for each cpu
	for i := 0; i < runtime.NumCPU(); i++ {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}

		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestListenerProcess", "-test.v")
		cmd.ExtraFiles = []*os.File{w}
		cmd.Env = append(cmd.Environ(),
			"GOMAXPROCS=1",
			"TEST_LISTENER_PROCESS_CPUID="+strconv.Itoa(i),
		)
		t.Log("Running", i)

		// capture output in case of error
		go func() {
			data, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatal(err, string(data))
			}
			t.Log("Running", string(data))
		}()
		t.Cleanup(func() {
			cmd.Process.Kill()
		})

		// Important! There isn't an automatic mapping between the id of a socket, and
		// the id of the CPU that the userland process (which opened the socket) is
		// running on. The "id" of the socket is determined by the order in which
		// sockets are opened. So it works best if the order in which the sockets are
		// opened is controlled to match the order in which processes are pinned to CPUs.
		//
		// Since fork() was being called inside the loop, the order in which the sockets
		// got opened in the child processes was not deterministic. In some cases the
		// process that was pinned to CPU 0 would actually end up being the third process
		// to open a socket, so it would end up getting packets that had been received on
		// the kernel side by CPU 2.
		//
		// To resolve this, I am using pipe to communicate between the parent and child
		// processes and ensure that the forking happens sequentially and the order of
		// the sockets being opened matches the order of the CPUs being pinned.
		//
		// wait for subprocess to become ready
		b := make([]byte, 1)
		_, err = r.Read(b)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Log("Done", runtime.NumCPU())

	// The sending code artificially moves itself to run on different core ids
	// and sends one message from each core. Since these packets are delivered
	// over loopback, they should  arrive on the same core that sent them.
	for i := 0; i < runtime.NumCPU(); i++ {
		// setup affinity
		var cpuset unix.CPUSet
		cpuset.Set(i)
		err := unix.SchedSetaffinity(0, &cpuset)
		if err != nil {
			t.Fatal(err)
		}

		want := []byte(strconv.Itoa(i))

		c, err := net.Dial("tcp", *address)
		if err != nil {
			t.Fatal(err)
		}

		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(want, got) {
			t.Errorf("TestListenerWithReuseport() mismatch (-want +got):\n-%s\n+%s", want, got)
		}
	}
}

const (
	SKF_AD_OFF              = -0x1000
	SKF_AD_PROTOCOL         = 0
	SKF_AD_PKTTYPE          = 4
	SKF_AD_IFINDEX          = 8
	SKF_AD_NLATTR           = 12
	SKF_AD_NLATTR_NEST      = 16
	SKF_AD_MARK             = 20
	SKF_AD_QUEUE            = 24
	SKF_AD_HATYPE           = 28
	SKF_AD_RXHASH           = 32
	SKF_AD_CPU              = 36
	SKF_AD_ALU_XOR_X        = 40
	SKF_AD_VLAN_TAG         = 44
	SKF_AD_VLAN_TAG_PRESENT = 48
	SKF_AD_PAY_OFFSET       = 52
	SKF_AD_RANDOM           = 56
	SKF_AD_VLAN_TPID        = 60
	SKF_AD_MAX              = 64
)
