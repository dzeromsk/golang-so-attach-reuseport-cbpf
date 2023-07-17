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