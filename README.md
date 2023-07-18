# golang-so-attach-reuseport-cbpf

Test functionality of BPF filters with `SO_REUSEPORT` and `SO_ATTACH_REUSEPORT_CBPF`.

This test creates an `SO_REUSEPORT` receiver group containing one socket
per CPU core.

It then creates a BPF program that will select a socket from this group
based on the core id that receives the packet.

The sending code artificially moves itself to run on different core ids
and sends one message from each core. Since these packets are delivered
over loopback, they should  arrive on the same core that sent them.

The receiving code then ensures that the packet was received on the
socket for the corresponding core id.

### Snippet
```go
var rawSMPProcessorID = SKF_AD_OFF + SKF_AD_CPU

var code = [...]unix.SockFilter{
	{unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, 0, 0, uint32(rawSMPProcessorID)}, // A = raw_smp_processor_id()
	{unix.BPF_RET | unix.BPF_A, 0, 0, 0},                                       // return A
}

var prog = unix.SockFprog{
	Len:    uint16(len(code)),
	Filter: &code[0],
}

err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
if err != nil {
  return
}

err = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, &prog)
if err != nil {
  return
}
```
