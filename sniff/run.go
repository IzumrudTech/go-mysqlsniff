package sniff

import (
	"fmt"
	"log"
	"time"

	"github.com/kirillDanshin/myutils"
	"github.com/kirillDanshin/netutils"
	"github.com/IzumrudTech/go-dbsniff/defaults"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/pcap"
)

// Run the instance
func (i *Instance) Run() error {
	defer myutils.CPUProf()()

	var (
		snapLen     = i.SnapLen
		promiscuous = defaults.Promiscuous
		timeout     = defaults.Timeout
		err         error
		handle      *pcap.Handle

		port = i.Addr.Port
	)

	i.device, err = netutils.FindIfaceWithAddr(i.Addr.IP.String(), true)
	myutils.LogFatalError(err)
	dlogClr.F("found %s interface", i.device)
	i.defragger = ip4defrag.NewIPv4Defragmenter()

	// Open device
	handle, err = pcap.OpenLive(
		i.device,
		snapLen,
		promiscuous,
		timeout,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("ip and port %d", port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	dlogClr.F("Only capturing port %d packets.", port)

	go syncPrinter(syncPrint)

	pSrc := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	pSrc.Lazy = i.Lazy
	count := 0
	bytes := int64(0)
	start := time.Now()
	go i.processPackets()
	for packet := range pSrc.Packets() {
		count++
		bytes += int64(len(packet.Data()))

		i.queue <- packet
	}

	close(syncPrint)

	dlogClr.F("Processed %d packets (%d bytes)", count, bytes)
	dlogClr.F("Uptime %s", time.Since(start))

	return nil
}
