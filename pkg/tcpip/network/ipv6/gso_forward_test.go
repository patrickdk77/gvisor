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

package ipv6

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	gsoFwdOutMTU  = 1486
	gsoFwdSeq     = 5000
	gsoFwdAck     = 7000
	gsoFwdSrcPort = 1000
	gsoFwdDstPort = 80
	gsoFwdTCPLen  = header.TCPMinimumSize
)

// newGSOTCPPacket6 returns a TCP packet carrying payloadLen bytes as one GSO
// packet of mss-sized segments, with the partial checksum a host leaves for
// offload, as a link endpoint receives it from a host that coalesced or never
// split the segments. With csumComplete, the packet instead carries the metadata of a host
// that coalesced segments it had already verified, with no partial checksum.
func newGSOTCPPacket6(payloadLen int, mss uint16, flags header.TCPFlags, csumComplete bool) *stack.PacketBuffer {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	hdr := prependable.New(header.IPv6MinimumSize + gsoFwdTCPLen)
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
	tcpHdr.SetChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, remoteIPv6Addr1, remoteIPv6Addr2, uint16(gsoFwdTCPLen+payloadLen)))
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(gsoFwdTCPLen + payloadLen),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           remoteIPv6Addr1,
		DstAddr:           remoteIPv6Addr2,
	})

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append(hdr.View(), payload...)),
	})
	pkt.GSOOptions = stack.GSO{
		Type:       stack.GSOTCPv6,
		NeedsCsum:  true,
		CsumOffset: header.TCPChecksumOffset,
		MSS:        mss,
		L3HdrLen:   header.IPv6MinimumSize,
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
		fitMSS     = gsoFwdOutMTU - header.IPv6MinimumSize - gsoFwdTCPLen
		payloadLen = 3*fitMSS + 100
	)
	tests := []struct {
		name         string
		mss          uint16
		flags        header.TCPFlags
		csumComplete bool
		outGSO       stack.SupportedGSO
		wantTooBig   bool
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
			name:       "segments too big for the outgoing MTU",
			mss:        fitMSS + 14,
			flags:      header.TCPFlagAck,
			wantTooBig: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				Clock:              faketime.NewManualClock(),
			})
			defer func() {
				s.Close()
				s.Wait()
				refs.DoRepeatedLeakCheck()
			}()

			in := channel.New(1, header.IPv6MinimumMTU, "")
			defer in.Close()
			out := channel.New(8, gsoFwdOutMTU, "")
			out.SupportedGSOKind = test.outGSO
			defer out.Close()
			for nicID, ep := range map[tcpip.NICID]*channel.Endpoint{incomingNICID: in, outgoingNICID: out} {
				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: ProtocolNumber, AddressWithPrefix: defaultEndpointConfigs[nicID]}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
			}
			s.SetRouteTable([]tcpip.Route{
				{Destination: incomingIPv6Addr.Subnet(), NIC: incomingNICID},
				{Destination: outgoingIPv6Addr.Subnet(), NIC: outgoingNICID},
			})
			if err := s.SetForwardingDefaultAndAllNICs(ProtocolNumber, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ProtocolNumber, err)
			}

			pkt := newGSOTCPPacket6(payloadLen, test.mss, test.flags, test.csumComplete)
			defer pkt.DecRef()
			in.InjectInbound(ProtocolNumber, pkt)

			reply := in.Read()
			if test.wantTooBig {
				if reply == nil {
					t.Fatalf("got no ICMPv6 error on the incoming NIC, want packet too big")
				}
				defer reply.DecRef()
				v := stack.PayloadSince(reply.NetworkHeader())
				defer v.Release()
				checker.IPv6(t, v, checker.ICMPv6(checker.ICMPv6Type(header.ICMPv6PacketTooBig)))
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
				if got, want := p.GSOOptions.Type, stack.GSOTCPv6; got != want {
					t.Errorf("forwarded GSOOptions.Type = %d, want %d", got, want)
				}
				if got, want := p.GSOOptions.MSS, test.mss; got != want {
					t.Errorf("forwarded GSOOptions.MSS = %d, want %d", got, want)
				}
				v := stack.PayloadSince(p.NetworkHeader())
				defer v.Release()
				if got, want := int(header.IPv6(v.AsSlice()).PayloadLength()), gsoFwdTCPLen+payloadLen; got != want {
					t.Errorf("forwarded IPv6 payload length = %d, want %d", got, want)
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
					checker.IPv6(t, v,
						checker.SrcAddr(remoteIPv6Addr1),
						checker.DstAddr(remoteIPv6Addr2),
						checker.TTL(63),
						checker.PayloadLen(gsoFwdTCPLen+n),
						checker.TCP(
							checker.TCPSeqNum(seq),
							checker.TCPAckNum(gsoFwdAck),
							checker.TCPFlags(wantFlags),
						),
					)
					if got := header.TCP(header.IPv6(v.AsSlice()).Payload()).Payload(); len(got) != n || got[0] != byte(seq-gsoFwdSeq) {
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
