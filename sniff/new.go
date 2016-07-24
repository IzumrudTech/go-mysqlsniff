package sniff

import (
	"fmt"
	"net"
	"runtime"

	"github.com/IzumrudTech/go-dbsniff/defaults"
	"github.com/google/gopacket"
	"github.com/ivpusic/grpool"
)

// NewInstance is a constructor for Instance
func NewInstance(config *Config) (*Instance, error) {
	if config == nil {
		return nil, fmt.Errorf("Instance config required, nil provided")
	}
	return newInst(config)
}

func newInst(cfg *Config) (*Instance, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("Can't use empty address")
	}
	var (
		snaplen = cfg.SnapshotLength
		Lazy    = cfg.Lazy
	)
	if snaplen == 0 {
		dlogClr.F("using default SnapshotLength %v for %v", defaults.SnapLen, cfg.Address)
		if defaults.SnapLen == 0 {
			return nil, fmt.Errorf("config.SnapshotLength equals to zero and no valid default value provided")
		}
		snaplen = defaults.SnapLen
	}

	addr, err := net.ResolveTCPAddr(defaults.Net, cfg.Address)
	if err != nil {
		return nil, err
	}

	numCPU := runtime.NumCPU()
	if numCPU > 2 { // we want to work faster but don't use much CPU
		numCPU = 2
	}

	return &Instance{
		Addr:     addr,
		SnapLen:  snaplen,
		Lazy:     Lazy,
		queue:    make(chan gopacket.Packet, 1024),
		pool:     grpool.NewPool(numCPU, 1024),
		registry: new(registry),
	}, nil
}
