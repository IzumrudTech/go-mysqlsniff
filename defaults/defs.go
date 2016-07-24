// Package defaults provides default read-only settings
// for ok-mysql
package defaults

import "github.com/google/gopacket/pcap"

const (
	// SnapLen is default pcap snaphost length
	SnapLen int32 = 65535

	// Timeout is default pcap timeout
	Timeout = pcap.BlockForever

	// Promiscuous is default promiscuous mode status
	Promiscuous = false

	// Net is default network to use
	Net = "tcp4"
)
