package main

import (
	"flag"
	"runtime"

	"net/http"
	_ "net/http/pprof"

	"github.com/IzumrudTech/go-dbsniff/sniff"
	"github.com/kirillDanshin/myutils"
)

var (
	addr    = flag.String("addr", "", "address to listen (required)")
	debAddr = flag.String("debugAddr", "", "address to listen for pprof")
)

func main() {
	flag.Parse()
	myutils.RequiredStrFatal("address", *addr)

	if *debAddr != "" {
		runtime.SetCPUProfileRate(1024)
		go http.ListenAndServe(*debAddr, http.DefaultServeMux)
	}

	instance, err := sniff.NewInstance(
		&sniff.Config{
			Address: *addr,
		},
	)
	myutils.LogFatalError(err)
	err = instance.Run()
	myutils.LogFatalError(err)

}
