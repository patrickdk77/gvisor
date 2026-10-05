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

package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NeedsTCPSegmentation returns whether pkt is a TCP packet that carries GSO
// metadata and more than one segment's worth of payload.
func (pk *PacketBuffer) NeedsTCPSegmentation() bool {
	gso := pk.GSOOptions
	return (gso.Type == GSOTCPv4 || gso.Type == GSOTCPv6) &&
		gso.MSS != 0 &&
		pk.TransportProtocolNumber == header.TCPProtocolNumber &&
		len(pk.TransportHeader().Slice()) >= header.TCPMinimumSize &&
		pk.Data().Size() > int(gso.MSS)
}

// SegmentTCPForForwarding splits pk, a forwarded TCP packet for which
// NeedsTCPSegmentation is true, into packets carrying at most
// pk.GSOOptions.MSS bytes of payload each, as a host splits a GSO packet when
// it transmits it. Each segment has complete IP and TCP checksums, no GSO
// metadata, and the forwarding state of pk. The caller owns the segments.
//
// Preconditions: pk.NeedsTCPSegmentation().
func (pk *PacketBuffer) SegmentTCPForForwarding(reservedHeaderBytes int) []*PacketBuffer {
	netHdr := pk.NetworkHeader().Slice()
	tcpHdr := header.TCP(pk.TransportHeader().Slice())
	data := pk.Data().ToBuffer()
	defer data.Release()

	mss := int(pk.GSOOptions.MSS)
	total := int(data.Size())
	seq := tcpHdr.SequenceNumber()
	flags := tcpHdr.Flags()
	segs := make([]*PacketBuffer, 0, (total+mss-1)/mss)
	for off := 0; off < total; off += mss {
		n := min(mss, total-off)
		chunk := data.Clone()
		chunk.TrimFront(int64(off))
		chunk.Truncate(int64(n))
		seg := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: reservedHeaderBytes + len(netHdr) + len(tcpHdr),
			Payload:            chunk,
			IsForwardedPacket:  true,
		})

		th := header.TCP(seg.TransportHeader().Push(len(tcpHdr)))
		copy(th, tcpHdr)
		th.SetSequenceNumber(seq + uint32(off))
		segFlags := flags
		if off+n < total {
			segFlags &^= header.TCPFlagFin | header.TCPFlagPsh
		}
		if off > 0 {
			segFlags &^= header.TCPFlagCwr
		}
		th.SetFlags(uint8(segFlags))
		seg.TransportProtocolNumber = header.TCPProtocolNumber

		nh := seg.NetworkHeader().Push(len(netHdr))
		copy(nh, netHdr)
		seg.NetworkProtocolNumber = pk.NetworkProtocolNumber
		tcpLen := len(tcpHdr) + n
		var src, dst tcpip.Address
		switch pk.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			ip := header.IPv4(nh)
			ip.SetTotalLength(uint16(len(nh) + tcpLen))
			ip.SetID(ip.ID() + uint16(off/mss))
			ip.SetChecksum(0)
			ip.SetChecksum(^ip.CalculateChecksum())
			src, dst = ip.SourceAddress(), ip.DestinationAddress()
		case header.IPv6ProtocolNumber:
			ip := header.IPv6(nh)
			ip.SetPayloadLength(uint16(len(nh) - header.IPv6MinimumSize + tcpLen))
			src, dst = ip.SourceAddress(), ip.DestinationAddress()
		}

		th.SetChecksum(0)
		xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(tcpLen))
		xsum = checksum.Combine(xsum, seg.Data().Checksum())
		th.SetChecksum(^th.CalculateChecksum(xsum))

		seg.tuple = pk.tuple
		seg.Mark = pk.Mark
		seg.InputNICID = pk.InputNICID
		seg.Hash = pk.Hash
		segs = append(segs, seg)
	}
	return segs
}
