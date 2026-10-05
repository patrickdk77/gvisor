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

package ipv4_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	gsoFwdOutMTU   = 1486
	gsoFwdSeq      = 5000
	gsoFwdAck      = 7000
	gsoFwdSrcPort  = 1000
	gsoFwdDstPort  = 80
	gsoFwdIPHdrLen = header.IPv4MinimumSize
	gsoFwdTCPLen   = header.TCPMinimumSize
)

// newGSOTCPPacket returns a TCP packet carrying payloadLen bytes as one GSO
// packet of mss-sized segments, with the partial checksum a host leaves for
// offload, as a link endpoint receives it from a host that coalesced or never
// split the segments. With csumComplete, the packet instead carries the metadata of a host
// that coalesced segments it had already verified, with no partial checksum.
func newGSOTCPPacket(payloadLen int, mss uint16, flags header.TCPFlags, csumComplete bool) *stack.PacketBuffer {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	hdr := prependable.New(gsoFwdIPHdrLen + gsoFwdTCPLen)
	tcpHdr := header.TCP(hdr.Prepend(gsoFwdTCPLen))
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    gsoFwdSrcPort,
		DstPort:    gsoFwdDstPort,
		SeqNum:     gsoFwdSeq,
		AckNum:     gsoFwdAck,
		DataOffset: gsoFwdTCPLen,
		Flags:      flags,
		WindowSize: 1000,
	})
	tcpHdr.SetChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, remoteIPv4Addr1, remoteIPv4Addr2, uint16(gsoFwdTCPLen+payloadLen)))
	ip := header.IPv4(hdr.Prepend(gsoFwdIPHdrLen))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(gsoFwdIPHdrLen + gsoFwdTCPLen + payloadLen),
		ID:          100,
		Flags:       header.IPv4FlagDontFragment,
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     remoteIPv4Addr1,
		DstAddr:     remoteIPv4Addr2,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append(hdr.View(), payload...)),
	})
	pkt.GSOOptions = stack.GSO{
		Type:       stack.GSOTCPv4,
		NeedsCsum:  true,
		CsumOffset: header.TCPChecksumOffset,
		MSS:        mss,
		L3HdrLen:   gsoFwdIPHdrLen,
	}
	if csumComplete {
		pkt.GSOOptions.NeedsCsum = false
		pkt.GSOOptions.CsumOffset = 0
		pkt.GSOOptions.L3HdrLen = 0
	}
	pkt.RXChecksumValidated = true
	return pkt
}

// TestForwardTCPGSO tests forwarding a TCP packet that the link layer
// received as one GSO packet of several segments.
func TestForwardTCPGSO(t *testing.T) {
	const (
		fitMSS     = gsoFwdOutMTU - gsoFwdIPHdrLen - gsoFwdTCPLen
		payloadLen = 3*fitMSS + 100
	)
	tests := []struct {
		name         string
		mss          uint16
		flags        header.TCPFlags
		csumComplete bool
		outGSO       stack.SupportedGSO
		wantICMP     bool
		wantWhole    bool
	}{
		{
			name:  "segmented to fit the outgoing MTU",
			mss:   fitMSS,
			flags: header.TCPFlagAck | header.TCPFlagPsh | header.TCPFlagFin,
		},
		{
			name:      "forwarded whole to a host GSO link",
			mss:       fitMSS,
			flags:     header.TCPFlagAck | header.TCPFlagPsh,
			outGSO:    stack.HostGSOSupported,
			wantWhole: true,
		},
		{
			name:         "segmented for a host GSO link without a partial checksum",
			mss:          fitMSS,
			flags:        header.TCPFlagAck | header.TCPFlagPsh,
			csumComplete: true,
			outGSO:       stack.HostGSOSupported,
		},
		{
			name:     "segments too big for the outgoing MTU with DF",
			mss:      fitMSS + 14,
			flags:    header.TCPFlagAck,
			wantICMP: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				Clock:              faketime.NewManualClock(),
			})
			defer func() {
				s.Close()
				s.Wait()
				refs.DoRepeatedLeakCheck()
			}()

			in := channel.New(1, ipv4.MaxTotalSize, "")
			defer in.Close()
			out := channel.New(8, gsoFwdOutMTU, "")
			out.SupportedGSOKind = test.outGSO
			defer out.Close()
			for nicID, ep := range map[tcpip.NICID]*channel.Endpoint{incomingNICID: in, outgoingNICID: out} {
				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: defaultEndpointConfigs[nicID]}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
			}
			s.SetRouteTable([]tcpip.Route{
				{Destination: incomingIPv4Addr.Subnet(), NIC: incomingNICID},
				{Destination: outgoingIPv4Addr.Subnet(), NIC: outgoingNICID},
			})
			if err := s.SetForwardingDefaultAndAllNICs(header.IPv4ProtocolNumber, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", header.IPv4ProtocolNumber, err)
			}

			pkt := newGSOTCPPacket(payloadLen, test.mss, test.flags, test.csumComplete)
			defer pkt.DecRef()
			in.InjectInbound(header.IPv4ProtocolNumber, pkt)

			reply := in.Read()
			if test.wantICMP {
				if reply == nil {
					t.Fatalf("got no ICMP error on the incoming NIC, want fragmentation needed")
				}
				defer reply.DecRef()
				v := stack.PayloadSince(reply.NetworkHeader())
				defer v.Release()
				checker.IPv4(t, v, checker.ICMPv4(
					checker.ICMPv4Type(header.ICMPv4DstUnreachable),
					checker.ICMPv4Code(header.ICMPv4FragmentationNeeded),
				))
				if got := header.ICMPv4(header.IPv4(v.AsSlice()).Payload()).MTU(); got != gsoFwdOutMTU {
					t.Errorf("ICMP next-hop MTU = %d, want %d", got, gsoFwdOutMTU)
				}
				if p := out.Read(); p != nil {
					p.DecRef()
					t.Errorf("got a packet on the outgoing NIC, want none")
				}
				return
			}
			if reply != nil {
				reply.DecRef()
				t.Fatalf("got a packet on the incoming NIC, want none")
			}

			if test.wantWhole {
				p := out.Read()
				if p == nil {
					t.Fatalf("got no packet on the outgoing NIC")
				}
				defer p.DecRef()
				if got, want := p.GSOOptions.Type, stack.GSOTCPv4; got != want {
					t.Errorf("forwarded GSOOptions.Type = %d, want %d", got, want)
				}
				if got, want := p.GSOOptions.MSS, test.mss; got != want {
					t.Errorf("forwarded GSOOptions.MSS = %d, want %d", got, want)
				}
				v := stack.PayloadSince(p.NetworkHeader())
				defer v.Release()
				if got, want := int(header.IPv4(v.AsSlice()).TotalLength()), gsoFwdIPHdrLen+gsoFwdTCPLen+payloadLen; got != want {
					t.Errorf("forwarded IPv4 total length = %d, want %d", got, want)
				}
				wantXsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, remoteIPv4Addr1, remoteIPv4Addr2, uint16(gsoFwdTCPLen+payloadLen))
				if got := header.TCP(header.IPv4(v.AsSlice()).Payload()).Checksum(); got != wantXsum {
					t.Errorf("forwarded TCP checksum = %#x, want the partial checksum %#x for the host to complete", got, wantXsum)
				}
				if p := out.Read(); p != nil {
					p.DecRef()
					t.Errorf("got a second packet on the outgoing NIC, want one")
				}
				return
			}

			seq := uint32(gsoFwdSeq)
			for remaining := payloadLen; remaining > 0; {
				n := min(remaining, int(test.mss))
				remaining -= n
				p := out.Read()
				if p == nil {
					t.Fatalf("got no segment at seq %d on the outgoing NIC", seq)
				}
				wantFlags := test.flags
				if remaining > 0 {
					wantFlags &^= header.TCPFlagPsh | header.TCPFlagFin
				}
				func() {
					defer p.DecRef()
					v := stack.PayloadSince(p.NetworkHeader())
					defer v.Release()
					checker.IPv4(t, v,
						checker.SrcAddr(remoteIPv4Addr1),
						checker.DstAddr(remoteIPv4Addr2),
						checker.TTL(63),
						checker.IPFullLength(uint16(gsoFwdIPHdrLen+gsoFwdTCPLen+n)),
						checker.TCP(
							checker.TCPSeqNum(seq),
							checker.TCPAckNum(gsoFwdAck),
							checker.TCPFlags(wantFlags),
						),
					)
					if got := header.TCP(header.IPv4(v.AsSlice()).Payload()).Payload(); len(got) != n || got[0] != byte(seq-gsoFwdSeq) {
						t.Errorf("segment at seq %d carries %d bytes, want %d bytes starting %#x", seq, len(got), n, byte(seq-gsoFwdSeq))
					}
				}()
				seq += uint32(n)
			}
			if p := out.Read(); p != nil {
				p.DecRef()
				t.Errorf("got an extra packet on the outgoing NIC")
			}
		})
	}
}
