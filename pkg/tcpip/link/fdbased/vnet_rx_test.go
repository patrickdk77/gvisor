// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fdbased

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestDispatchVnetHdrGSO tests that the GSO metadata a host sends in the
// virtio-net header of a received packet is kept on the packet.
func TestDispatchVnetHdrGSO(t *testing.T) {
	const (
		mss        = 1448
		payloadLen = 3 * mss

		// _VIRTIO_NET_HDR_F_DATA_VALID marks a packet whose checksum the host
		// already verified, as for segments it coalesced with GRO.
		_VIRTIO_NET_HDR_F_DATA_VALID = 2
	)
	ethHdr := []byte{
		1, 2, 3, 4, 5, 60,
		1, 2, 3, 4, 5, 61,
		8, 0,
	}
	ipv4Pkt := func() []byte {
		b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+payloadLen)
		header.IPv4(b).Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         64,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
			DstAddr:     tcpip.AddrFrom4([4]byte{192, 168, 0, 2}),
		})
		header.TCP(b[header.IPv4MinimumSize:]).Encode(&header.TCPFields{SrcPort: 80, DstPort: 81, DataOffset: header.TCPMinimumSize})
		return b
	}
	ipv6Pkt := func() []byte {
		b := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize+payloadLen)
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(header.TCPMinimumSize + payloadLen),
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           tcpip.AddrFrom16([16]byte{0xfe, 0x80, 15: 1}),
			DstAddr:           tcpip.AddrFrom16([16]byte{0xfe, 0x80, 15: 2}),
		})
		header.TCP(b[header.IPv6MinimumSize:]).Encode(&header.TCPFields{SrcPort: 80, DstPort: 81, DataOffset: header.TCPMinimumSize})
		return b
	}
	ethType6 := []byte{
		1, 2, 3, 4, 5, 60,
		1, 2, 3, 4, 5, 61,
		0x86, 0xdd,
	}

	for _, dsp := range []struct {
		name          string
		newDispatcher func(fd int, e *endpoint, opts *Options) (linkDispatcher, error)
	}{
		{name: "readVDispatcher", newDispatcher: newReadVDispatcher},
		{name: "recvMMsgDispatcher", newDispatcher: newRecvMMsgDispatcher},
	} {
		for _, test := range []struct {
			name    string
			ethHdr  []byte
			netPkt  []byte
			vnetHdr virtioNetHdr
			want    stack.GSO
		}{
			{
				name:   "TCPv4",
				ethHdr: ethHdr,
				netPkt: ipv4Pkt(),
				vnetHdr: virtioNetHdr{
					flags:      _VIRTIO_NET_HDR_F_NEEDS_CSUM,
					gsoType:    _VIRTIO_NET_HDR_GSO_TCPV4,
					hdrLen:     header.EthernetMinimumSize + header.IPv4MinimumSize + header.TCPMinimumSize,
					gsoSize:    mss,
					csumStart:  header.EthernetMinimumSize + header.IPv4MinimumSize,
					csumOffset: header.TCPChecksumOffset,
				},
				want: stack.GSO{
					Type:       stack.GSOTCPv4,
					NeedsCsum:  true,
					CsumOffset: header.TCPChecksumOffset,
					MSS:        mss,
					L3HdrLen:   header.IPv4MinimumSize,
				},
			},
			{
				name:   "TCPv4 with ECN",
				ethHdr: ethHdr,
				netPkt: ipv4Pkt(),
				vnetHdr: virtioNetHdr{
					flags:      _VIRTIO_NET_HDR_F_NEEDS_CSUM,
					gsoType:    _VIRTIO_NET_HDR_GSO_TCPV4 | _VIRTIO_NET_HDR_GSO_ECN,
					hdrLen:     header.EthernetMinimumSize + header.IPv4MinimumSize + header.TCPMinimumSize,
					gsoSize:    mss,
					csumStart:  header.EthernetMinimumSize + header.IPv4MinimumSize,
					csumOffset: header.TCPChecksumOffset,
				},
				want: stack.GSO{
					Type:       stack.GSOTCPv4,
					NeedsCsum:  true,
					CsumOffset: header.TCPChecksumOffset,
					MSS:        mss,
					L3HdrLen:   header.IPv4MinimumSize,
				},
			},
			{
				name:   "TCPv6",
				ethHdr: ethType6,
				netPkt: ipv6Pkt(),
				vnetHdr: virtioNetHdr{
					flags:      _VIRTIO_NET_HDR_F_NEEDS_CSUM,
					gsoType:    _VIRTIO_NET_HDR_GSO_TCPV6,
					hdrLen:     header.EthernetMinimumSize + header.IPv6MinimumSize + header.TCPMinimumSize,
					gsoSize:    mss,
					csumStart:  header.EthernetMinimumSize + header.IPv6MinimumSize,
					csumOffset: header.TCPChecksumOffset,
				},
				want: stack.GSO{
					Type:       stack.GSOTCPv6,
					NeedsCsum:  true,
					CsumOffset: header.TCPChecksumOffset,
					MSS:        mss,
					L3HdrLen:   header.IPv6MinimumSize,
				},
			},
			{
				name:   "TCPv4 coalesced with a verified checksum",
				ethHdr: ethHdr,
				netPkt: ipv4Pkt(),
				vnetHdr: virtioNetHdr{
					flags:   _VIRTIO_NET_HDR_F_DATA_VALID,
					gsoType: _VIRTIO_NET_HDR_GSO_TCPV4,
					hdrLen:  header.EthernetMinimumSize + header.IPv4MinimumSize + header.TCPMinimumSize,
					gsoSize: mss,
				},
				want: stack.GSO{
					Type: stack.GSOTCPv4,
					MSS:  mss,
				},
			},
			{
				name:   "checksum offload without GSO",
				ethHdr: ethHdr,
				netPkt: ipv4Pkt(),
				vnetHdr: virtioNetHdr{
					flags:      _VIRTIO_NET_HDR_F_NEEDS_CSUM,
					csumStart:  header.EthernetMinimumSize + header.IPv4MinimumSize,
					csumOffset: header.TCPChecksumOffset,
				},
				want: stack.GSO{},
			},
		} {
			t.Run(dsp.name+"/"+test.name, func(t *testing.T) {
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fds[0])
				defer unix.Close(fds[1])

				frame := append(test.vnetHdr.marshal(), test.ethHdr...)
				frame = append(frame, test.netPkt...)
				if err := unix.Sendmsg(fds[1], frame, nil, nil, 0); err != nil {
					t.Fatal(err)
				}

				sink := &fakeNetworkDispatcher{}
				d, err := dsp.newDispatcher(fds[0], &endpoint{
					addr:       tcpip.LinkAddress(test.ethHdr[:header.EthernetAddressSize]),
					hdrSize:    len(test.ethHdr),
					dispatcher: sink,
					gsoKind:    stack.HostGSOSupported,
				}, &Options{ProcessorsPerChannel: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer d.release()
				if ok, err := d.dispatch(); !ok || err != nil {
					t.Fatalf("d.dispatch() = %v, %v", ok, err)
				}

				if got, want := len(sink.pkts), 1; got != want {
					t.Fatalf("len(sink.pkts) = %d, want %d", got, want)
				}
				pkt := sink.pkts[0]
				defer pkt.DecRef()
				if got, want := pkt.Data().Size(), len(test.netPkt); got != want {
					t.Errorf("pkt.Data().Size() = %d, want %d", got, want)
				}
				if pkt.GSOOptions != test.want {
					t.Errorf("pkt.GSOOptions = %+v, want %+v", pkt.GSOOptions, test.want)
				}
			})
		}
	}
}
