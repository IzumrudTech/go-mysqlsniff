package main

import (
	"flag"

	"github.com/IzumrudTech/go-dbsniff/sniff"
	"github.com/kirillDanshin/myutils"
)

var (
	addr = flag.String("addr", "", "address to listen (required)")
)

func main() {
	flag.Parse()
	myutils.RequiredStrFatal("address", *addr)

	instance, err := sniff.NewInstance(
		&sniff.Config{
			Address: *addr,
		},
	)
	myutils.LogFatalError(err)
	err = instance.Run()
	myutils.LogFatalError(err)

}
