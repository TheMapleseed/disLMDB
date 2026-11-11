package dislmdb

/*
#include "dislmdb.h"
*/
import "C"

import (
	"sync"
	"unsafe"
)

var (
	scanMu   sync.Mutex
	scanNext uintptr = 1
	scanTabs          = map[uintptr]*[]IndexEntry{}
)

func registerScan(out *[]IndexEntry) uintptr {
	scanMu.Lock()
	defer scanMu.Unlock()
	h := scanNext
	scanNext++
	scanTabs[h] = out
	return h
}

func unregisterScan(h uintptr) {
	scanMu.Lock()
	defer scanMu.Unlock()
	delete(scanTabs, h)
}

//export dislmdb_go_scan_cb
func dislmdb_go_scan_cb(sk, pk, pv *C.MDB_val, user unsafe.Pointer) C.int {
	h := uintptr(user)
	scanMu.Lock()
	out := scanTabs[h]
	scanMu.Unlock()
	if out == nil {
		return 1
	}
	*out = append(*out, IndexEntry{
		SecondaryKey: copyMDB(sk),
		PrimaryKey:   copyMDB(pk),
		PrimaryVal:   copyMDB(pv),
	})
	return 0
}
