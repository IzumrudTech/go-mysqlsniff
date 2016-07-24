package sniff

import dlog_orig "github.com/kirillDanshin/dlog"

var (
	syncPrint = make(chan string, 1024)
	dlogClr   = dlog_orig.WithCaller{}
)
