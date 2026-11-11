// Package dislmdb is a thin cgo binding over the DisLMDB C ABI (bindings/ABI.kdl).
//
// Build libdislmdb first (`make lib`), then:
//
//	make go-bindings
//
// or:
//
//	CGO_ENABLED=1 go test
package dislmdb

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I${SRCDIR}/../../src
#cgo LDFLAGS: -L${SRCDIR}/../../build/lib -ldislmdb -lz -lpthread
#cgo darwin LDFLAGS: -framework Security -Wl,-rpath,${SRCDIR}/../../build/lib
#cgo linux LDFLAGS: -lcrypto -luuid -Wl,-rpath,${SRCDIR}/../../build/lib

#include "dislmdb.h"
#include <stdlib.h>
#include <string.h>

extern int dislmdb_go_scan_cb(const MDB_val *sk, const MDB_val *pk,
                              const MDB_val *pv, void *user);

static int scan_trampoline(const MDB_val *sk, const MDB_val *pk,
                           const MDB_val *pv, void *user)
{
    return dislmdb_go_scan_cb(sk, pk, pv, user);
}

static int call_index_scan(DISLMDB_txn *txn, MDB_dbi primary, MDB_dbi index,
                           const MDB_val *prefix, size_t limit, void *user)
{
    return dislmdb_index_scan(txn, primary, index, NULL, prefix, limit,
                              scan_trampoline, user);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// ACL capability bits (match dislmdb_errors.h).
const (
	ACLRead  = 0x1
	ACLWrite = 0x2
	ACLAdmin = 0x4
	ACLAll   = ACLRead | ACLWrite | ACLAdmin
)

// Version returns the library version string and components.
func Version() (string, int, int, int) {
	var maj, min, pat C.int
	s := C.dislmdb_version(&maj, &min, &pat)
	if s == nil {
		return "", int(maj), int(min), int(pat)
	}
	return C.GoString(s), int(maj), int(min), int(pat)
}

// OpenOptions controls env open knobs mirrored from DISLMDB_env_config.
type OpenOptions struct {
	EnableACL bool
	MaxDBs    uint
}

// Env wraps DISLMDB_env.
type Env struct {
	raw  *C.DISLMDB_env
	path *C.char
}

// Open opens a SOLO environment at path (default config).
func Open(path string) (*Env, error) {
	return OpenWith(path, OpenOptions{})
}

// OpenWith opens with optional ACL / maxdbs overrides.
func OpenWith(path string, opts OpenOptions) (*Env, error) {
	var raw *C.DISLMDB_env
	if rc := C.dislmdb_env_create(&raw); rc != 0 {
		return nil, errRC(rc)
	}
	var cfg C.DISLMDB_env_config
	if rc := C.dislmdb_env_config_init(&cfg); rc != 0 {
		C.dislmdb_env_close(raw)
		return nil, errRC(rc)
	}
	cpath := C.CString(path)
	cfg.path = cpath
	if opts.MaxDBs != 0 {
		cfg.maxdbs = C.uint(opts.MaxDBs)
	} else {
		cfg.maxdbs = 16
	}
	cfg.network.local_port = 0
	if opts.EnableACL {
		cfg.enable_acl = true
	}
	if rc := C.dislmdb_env_open(raw, &cfg); rc != 0 {
		C.free(unsafe.Pointer(cpath))
		C.dislmdb_env_close(raw)
		return nil, errRC(rc)
	}
	return &Env{raw: raw, path: cpath}, nil
}

// Close releases the environment.
func (e *Env) Close() {
	if e == nil || e.raw == nil {
		return
	}
	C.dislmdb_env_close(e.raw)
	e.raw = nil
	if e.path != nil {
		C.free(unsafe.Pointer(e.path))
		e.path = nil
	}
}

// SetPrincipal sets the current ACL principal.
func (e *Env) SetPrincipal(name string) error {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	return errRC(C.dislmdb_acl_set_principal(e.raw, c))
}

// ACLGrantAll grants ALL bits to principal (bootstrap / admin).
func (e *Env) ACLGrantAll(principal string) error {
	c := C.CString(principal)
	defer C.free(unsafe.Pointer(c))
	return errRC(C.dislmdb_acl_grant(e.raw, c, C.uint(ACLAll)))
}

// ACLGrantPrefix grants READ/WRITE under a key prefix.
func (e *Env) ACLGrantPrefix(principal, prefix string, perms uint) error {
	p := C.CString(principal)
	pre := C.CString(prefix)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(pre))
	return errRC(C.dislmdb_acl_grant_prefix(e.raw, p, pre, C.uint(perms)))
}

// ACLRoleDefine defines or updates a role. Empty prefix ⇒ global.
func (e *Env) ACLRoleDefine(role, prefix string, perms uint) error {
	r := C.CString(role)
	defer C.free(unsafe.Pointer(r))
	var pfx *C.char
	if prefix != "" {
		pfx = C.CString(prefix)
		defer C.free(unsafe.Pointer(pfx))
	}
	return errRC(C.dislmdb_acl_role_define(e.raw, r, pfx, C.uint(perms)))
}

// ACLRoleUndefine removes a role and memberships.
func (e *Env) ACLRoleUndefine(role string) error {
	r := C.CString(role)
	defer C.free(unsafe.Pointer(r))
	return errRC(C.dislmdb_acl_role_undefine(e.raw, r))
}

// ACLRoleGet returns (perms, prefix) for a role.
func (e *Env) ACLRoleGet(role string) (uint, string, error) {
	r := C.CString(role)
	defer C.free(unsafe.Pointer(r))
	var perms C.unsigned
	buf := make([]byte, 128)
	rc := C.dislmdb_acl_role_get(e.raw, r, &perms, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if rc != 0 {
		return 0, "", errRC(rc)
	}
	return uint(perms), C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

// ACLRoleAssign assigns principal to role.
func (e *Env) ACLRoleAssign(principal, role string) error {
	p := C.CString(principal)
	r := C.CString(role)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(r))
	return errRC(C.dislmdb_acl_role_assign(e.raw, p, r))
}

// ACLRoleUnassign removes membership.
func (e *Env) ACLRoleUnassign(principal, role string) error {
	p := C.CString(principal)
	r := C.CString(role)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(r))
	return errRC(C.dislmdb_acl_role_unassign(e.raw, p, r))
}

// ACLEffective returns the effective global permission mask.
func (e *Env) ACLEffective(principal string) (uint, error) {
	p := C.CString(principal)
	defer C.free(unsafe.Pointer(p))
	var perms C.unsigned
	if rc := C.dislmdb_acl_effective(e.raw, p, &perms); rc != 0 {
		return 0, errRC(rc)
	}
	return uint(perms), nil
}

func mdbVal(b []byte) C.MDB_val {
	var v C.MDB_val
	v.mv_size = C.size_t(len(b))
	if len(b) > 0 {
		v.mv_data = unsafe.Pointer(&b[0])
	}
	return v
}

func copyMDB(v *C.MDB_val) []byte {
	if v == nil || v.mv_size == 0 || v.mv_data == nil {
		return nil
	}
	return C.GoBytes(v.mv_data, C.int(v.mv_size))
}

// Put writes key/value into named DBI.
func (e *Env) Put(db string, key, val []byte) error {
	return e.withWrite(db, func(txn *C.DISLMDB_txn, dbi C.MDB_dbi) error {
		k := mdbVal(key)
		v := mdbVal(val)
		return errRC(C.dislmdb_put(txn, dbi, &k, &v, 0))
	})
}

// Del deletes a key from named DBI.
func (e *Env) Del(db string, key []byte) error {
	return e.withWrite(db, func(txn *C.DISLMDB_txn, dbi C.MDB_dbi) error {
		k := mdbVal(key)
		return errRC(C.dislmdb_del(txn, dbi, &k, nil))
	})
}

// Get reads a key (nil, nil) on not found.
func (e *Env) Get(db string, key []byte) ([]byte, error) {
	var txn *C.DISLMDB_txn
	if rc := C.dislmdb_txn_begin(e.raw, nil, C.MDB_RDONLY, &txn); rc != 0 {
		return nil, errRC(rc)
	}
	defer C.dislmdb_txn_abort(txn)
	cdb := C.CString(db)
	defer C.free(unsafe.Pointer(cdb))
	var dbi C.MDB_dbi
	if rc := C.dislmdb_dbi_open(txn, cdb, 0, &dbi); rc != 0 {
		if rc == C.MDB_NOTFOUND {
			return nil, nil
		}
		return nil, errRC(rc)
	}
	k := mdbVal(key)
	var v C.MDB_val
	mtxn := C.dislmdb_get_lmdb_txn(txn)
	rc := C.mdb_get(mtxn, dbi, &k, &v)
	if rc == C.MDB_NOTFOUND {
		return nil, nil
	}
	if rc != 0 {
		return nil, errRC(rc)
	}
	return copyMDB(&v), nil
}

// IndexPut writes primary + secondary index in one txn.
func (e *Env) IndexPut(primaryDB, indexDB string, pkey, pval, skey []byte) error {
	return e.withIndexWrite(primaryDB, indexDB, func(txn *C.DISLMDB_txn, primary, index C.MDB_dbi) error {
		pk := mdbVal(pkey)
		pv := mdbVal(pval)
		sk := mdbVal(skey)
		return errRC(C.dislmdb_index_put(txn, primary, index, &pk, &pv, &sk, 0))
	})
}

// IndexDel removes primary row + index entry.
func (e *Env) IndexDel(primaryDB, indexDB string, pkey, skey []byte) error {
	return e.withIndexWrite(primaryDB, indexDB, func(txn *C.DISLMDB_txn, primary, index C.MDB_dbi) error {
		pk := mdbVal(pkey)
		sk := mdbVal(skey)
		return errRC(C.dislmdb_index_del(txn, primary, index, &pk, &sk))
	})
}

// IndexGet looks up via secondary key → (primaryKey, primaryVal).
func (e *Env) IndexGet(primaryDB, indexDB string, skey []byte) (pkey, pval []byte, err error) {
	err = e.withIndexRead(primaryDB, indexDB, func(txn *C.DISLMDB_txn, primary, index C.MDB_dbi) error {
		sk := mdbVal(skey)
		var pk, pv C.MDB_val
		rc := C.dislmdb_index_get(txn, primary, index, &sk, &pk, &pv)
		if rc == C.MDB_NOTFOUND {
			return nil
		}
		if rc != 0 {
			return errRC(rc)
		}
		pkey = copyMDB(&pk)
		pval = copyMDB(&pv)
		return nil
	})
	return pkey, pval, err
}

// IndexEntry is one row from IndexScan.
type IndexEntry struct {
	SecondaryKey []byte
	PrimaryKey   []byte
	PrimaryVal   []byte
}

// IndexScan walks the secondary index. prefix nil = no filter; limit 0 = unlimited.
func (e *Env) IndexScan(primaryDB, indexDB string, prefix []byte, limit uint) ([]IndexEntry, error) {
	var out []IndexEntry
	err := e.withIndexRead(primaryDB, indexDB, func(txn *C.DISLMDB_txn, primary, index C.MDB_dbi) error {
		var pfx *C.MDB_val
		var pfxVal C.MDB_val
		if prefix != nil {
			pfxVal = mdbVal(prefix)
			pfx = &pfxVal
		}
		handle := registerScan(&out)
		defer unregisterScan(handle)
		return errRC(C.call_index_scan(txn, primary, index, pfx, C.size_t(limit), unsafe.Pointer(uintptr(handle))))
	})
	return out, err
}

// PutVersioned stores BE-u64 version + payload (LWW).
func (e *Env) PutVersioned(db string, key, val []byte, version uint64) error {
	return e.withWrite(db, func(txn *C.DISLMDB_txn, dbi C.MDB_dbi) error {
		k := mdbVal(key)
		v := mdbVal(val)
		return errRC(C.dislmdb_put_versioned(txn, dbi, &k, &v, 0, C.uint64_t(version)))
	})
}

// GetVersioned returns (version, payload) or (0, nil, nil) if missing.
func (e *Env) GetVersioned(db string, key []byte) (uint64, []byte, error) {
	var txn *C.DISLMDB_txn
	if rc := C.dislmdb_txn_begin(e.raw, nil, C.MDB_RDONLY, &txn); rc != 0 {
		return 0, nil, errRC(rc)
	}
	defer C.dislmdb_txn_abort(txn)
	cdb := C.CString(db)
	defer C.free(unsafe.Pointer(cdb))
	var dbi C.MDB_dbi
	if rc := C.dislmdb_dbi_open(txn, cdb, 0, &dbi); rc != 0 {
		if rc == C.MDB_NOTFOUND {
			return 0, nil, nil
		}
		return 0, nil, errRC(rc)
	}
	k := mdbVal(key)
	var ver C.uint64_t
	var cap C.size_t
	rc := C.dislmdb_get_versioned(txn, dbi, &k, &ver, nil, &cap)
	if rc == C.MDB_NOTFOUND {
		return 0, nil, nil
	}
	if rc != 0 {
		return 0, nil, errRC(rc)
	}
	buf := make([]byte, cap)
	k2 := mdbVal(key)
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	rc = C.dislmdb_get_versioned(txn, dbi, &k2, &ver, ptr, &cap)
	if rc != 0 {
		return 0, nil, errRC(rc)
	}
	return uint64(ver), buf[:cap], nil
}

// ExportMetricsFile writes Prometheus text (live-safe).
func (e *Env) ExportMetricsFile(path string) error {
	var cpath *C.char
	if path != "" {
		cpath = C.CString(path)
		defer C.free(unsafe.Pointer(cpath))
	}
	return errRC(C.dislmdb_export_metrics_file(e.raw, cpath))
}

func (e *Env) withWrite(db string, f func(*C.DISLMDB_txn, C.MDB_dbi) error) error {
	var txn *C.DISLMDB_txn
	if rc := C.dislmdb_txn_begin(e.raw, nil, 0, &txn); rc != 0 {
		return errRC(rc)
	}
	cdb := C.CString(db)
	defer C.free(unsafe.Pointer(cdb))
	var dbi C.MDB_dbi
	if rc := C.dislmdb_dbi_open(txn, cdb, C.MDB_CREATE, &dbi); rc != 0 {
		C.dislmdb_txn_abort(txn)
		return errRC(rc)
	}
	if err := f(txn, dbi); err != nil {
		C.dislmdb_txn_abort(txn)
		return err
	}
	return errRC(C.dislmdb_txn_commit(txn))
}

func (e *Env) withIndexWrite(primaryDB, indexDB string, f func(*C.DISLMDB_txn, C.MDB_dbi, C.MDB_dbi) error) error {
	var txn *C.DISLMDB_txn
	if rc := C.dislmdb_txn_begin(e.raw, nil, 0, &txn); rc != 0 {
		return errRC(rc)
	}
	pname := C.CString(primaryDB)
	iname := C.CString(indexDB)
	defer C.free(unsafe.Pointer(pname))
	defer C.free(unsafe.Pointer(iname))
	var primary, index C.MDB_dbi
	if rc := C.dislmdb_dbi_open(txn, pname, C.MDB_CREATE, &primary); rc != 0 {
		C.dislmdb_txn_abort(txn)
		return errRC(rc)
	}
	if rc := C.dislmdb_dbi_open(txn, iname, C.MDB_CREATE, &index); rc != 0 {
		C.dislmdb_txn_abort(txn)
		return errRC(rc)
	}
	if err := f(txn, primary, index); err != nil {
		C.dislmdb_txn_abort(txn)
		return err
	}
	return errRC(C.dislmdb_txn_commit(txn))
}

func (e *Env) withIndexRead(primaryDB, indexDB string, f func(*C.DISLMDB_txn, C.MDB_dbi, C.MDB_dbi) error) error {
	var txn *C.DISLMDB_txn
	if rc := C.dislmdb_txn_begin(e.raw, nil, C.MDB_RDONLY, &txn); rc != 0 {
		return errRC(rc)
	}
	defer C.dislmdb_txn_abort(txn)
	pname := C.CString(primaryDB)
	iname := C.CString(indexDB)
	defer C.free(unsafe.Pointer(pname))
	defer C.free(unsafe.Pointer(iname))
	var primary, index C.MDB_dbi
	if rc := C.dislmdb_dbi_open(txn, pname, 0, &primary); rc != 0 {
		return errRC(rc)
	}
	if rc := C.dislmdb_dbi_open(txn, iname, 0, &index); rc != 0 {
		return errRC(rc)
	}
	return f(txn, primary, index)
}

func errRC(rc C.int) error {
	if rc == 0 {
		return nil
	}
	s := C.GoString(C.dislmdb_strerror(rc))
	return fmt.Errorf("%w: %s (%d)", errors.New("dislmdb"), s, int(rc))
}
