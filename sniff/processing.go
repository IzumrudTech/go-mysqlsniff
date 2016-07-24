package sniff

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kirillDanshin/dlog"
)

func (i *Instance) processPackets() {
	for packet := range i.queue {
		i.pool.WaitCount(1)
		i.pool.JobQueue <- func() {
			defer func() {
				recover()
				i.pool.JobDone()
			}()
			i.processPacket(packet)
		}
	}
	i.pool.WaitAll()
}

func (i *Instance) processPacket(packet gopacket.Packet) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return
	}
	ip4 := ip4Layer.(*layers.IPv4)
	l := ip4.Length
	newip4, err := i.defragger.DefragIPv4(ip4)
	if err != nil {
		dlogClr.Ln("Error while defragging", err)
	} else if newip4 == nil {
		dlogClr.Ln("Recieved a fragment")
		return
	}
	if newip4.Length != l {
		dlogClr.F("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
		pb, ok := packet.(gopacket.PacketBuilder)
		if !ok {
			dlogClr.Ln("Error while getting packet builder: it's not a PacketBuilder")
		}
		nextDecoder := newip4.NextLayerType()
		nextDecoder.Decode(newip4.Payload, pb)
	}

	bdlog := dlog.NewBuffered()
	defer func() {
		defer recover()
		// syncPrint <- fmt.Sprintf("packet: %s", packet)
		syncPrint <- bdlog.String()
		bdlog.Release()
	}()

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var ip *layers.IPv4
	if ipLayer != nil {
		ip, _ = ipLayer.(*layers.IPv4)
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		bdlog.Ln("TCP layer detected")
		tcp, _ := tcpLayer.(*layers.TCP)
		t := packet.Metadata().Timestamp
		p := packetInfo{
			Time: t,
			Ack:  tcp.Ack,
			FIN:  tcp.FIN,
		}
		i.registry.rwm.Lock()
		i.registry.store.Append(tcp.Ack, p)
		i.registry.rwm.Unlock()

		if tcp.FIN {
			i.registry.Process(tcp.Ack)
		}
		// i.registry[dst] = append(i.registry[dst], packetInfo{Time: t, Ack: tcp.Ack, ACK: tcp.ACK, FIN: tcp.FIN})
		// if i.registry[dst] == nil {
		// 	i.registry[dst] = &packets{
		// 		info: make([]packetInfo, 8),
		// 		mtx:  &sync.Mutex{},
		// 	}
		// }
		// i.registry[dst].mtx.Lock()
		// if len(i.registry[dst].info) == cap(i.registry[dst].info)-2 {
		// 	i.registry[dst].info = i.registry[dst].info[:len(i.registry[dst].info)*2]
		// }
		// i.registry[dst].info = append(
		// 	i.registry[dst].info,
		// 	packetInfo{
		// 		Time: t,
		// 		Ack:  tcp.Ack,
		// 		ACK:  tcp.ACK,
		// 		FIN:  tcp.FIN,
		// 	},
		// )
		// i.registry[dst].mtx.Unlock()
		fmt.Println("time=[", t.UnixNano(), "] dest=[", ip.DstIP, tcp.DstPort, "] src=[", ip.SrcIP, tcp.SrcPort, "] ACK n=[", tcp.Ack, "] PSH=[", tcp.PSH, "] FIN=[", tcp.FIN, "]")
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		bdlog.F("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		bdlog.Ln("Sequence number: ", tcp.Seq)
		bdlog.Ln("FIN: ", tcp.FIN)
		bdlog.Ln("SYN: ", tcp.SYN)
		bdlog.Ln("RST: ", tcp.RST)
		bdlog.Ln("PSH: ", tcp.PSH)
		bdlog.Ln("ACK: ", tcp.ACK, "n=", tcp.Ack)
		bdlog.Ln("URG: ", tcp.URG)
		bdlog.Ln("ECE: ", tcp.ECE)
		bdlog.Ln("CWR: ", tcp.CWR)
		bdlog.Ln("NS:  ", tcp.NS)
		bdlog.Ln()
	}

	app := packet.ApplicationLayer()
	bdlog.F("app.LayerPayload %+v", app.LayerPayload())

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		bdlog.Ln("Error decoding some part of the packet:", err)
	}

}
