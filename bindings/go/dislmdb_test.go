package dislmdb

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Env open binds a default UDP/TCP port; serialize opens across tests.
var envLock sync.Mutex

func tmpDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "dislmdb_go_"+time.Now().Format("150405.000000000"))
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestVersion(t *testing.T) {
	s, maj, _, _ := Version()
	if s == "" || maj < 0 {
		t.Fatalf("bad version %q %d", s, maj)
	}
}

func TestPutGetIndexVersioned(t *testing.T) {
	envLock.Lock()
	defer envLock.Unlock()
	dir := tmpDir(t)

	env, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()

	if err := env.Put("entities", []byte("hello"), []byte("world")); err != nil {
		t.Fatal(err)
	}
	got, err := env.Get("entities", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("world")) {
		t.Fatalf("got %q", got)
	}
	if err := env.Del("entities", []byte("hello")); err != nil {
		t.Fatal(err)
	}

	if err := env.IndexPut("entities", "idx_name", []byte{1, 2}, []byte("alice"), []byte("alice")); err != nil {
		t.Fatal(err)
	}
	pk, pv, err := env.IndexGet("entities", "idx_name", []byte("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk, []byte{1, 2}) || !bytes.Equal(pv, []byte("alice")) {
		t.Fatalf("index_get pk=%q pv=%q", pk, pv)
	}
	if err := env.IndexPut("entities", "idx_name", []byte("u2"), []byte("amy"), []byte("amy")); err != nil {
		t.Fatal(err)
	}
	if err := env.IndexPut("entities", "idx_name", []byte("u3"), []byte("bob"), []byte("bob")); err != nil {
		t.Fatal(err)
	}
	scanA, err := env.IndexScan("entities", "idx_name", []byte("a"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanA) != 2 {
		t.Fatalf("scan a want 2 got %d", len(scanA))
	}
	scanLim, err := env.IndexScan("entities", "idx_name", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanLim) != 1 {
		t.Fatalf("scan lim want 1 got %d", len(scanLim))
	}

	if err := env.PutVersioned("entities", []byte("doc"), []byte("v1"), 10); err != nil {
		t.Fatal(err)
	}
	if err := env.PutVersioned("entities", []byte("doc"), []byte("old"), 5); err == nil {
		t.Fatal("expected stale version reject")
	}
	ver, payload, err := env.GetVersioned("entities", []byte("doc"))
	if err != nil {
		t.Fatal(err)
	}
	if ver != 10 || !bytes.Equal(payload, []byte("v1")) {
		t.Fatalf("ver=%d payload=%q", ver, payload)
	}

	prom := filepath.Join(dir, "metrics.prom")
	if err := env.ExportMetricsFile(prom); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(prom)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 10 {
		t.Fatalf("metrics too short: %q", b)
	}
}

func TestRBAC(t *testing.T) {
	envLock.Lock()
	defer envLock.Unlock()
	dir := tmpDir(t)

	env, err := OpenWith(dir, OpenOptions{EnableACL: true, MaxDBs: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()

	if err := env.SetPrincipal("alice"); err != nil {
		t.Fatal(err)
	}
	if err := env.ACLGrantAll("alice"); err != nil {
		t.Fatal(err)
	}
	if err := env.ACLRoleDefine("writer", "", ACLRead|ACLWrite); err != nil {
		t.Fatal(err)
	}
	if err := env.ACLRoleDefine("tenant_dave", "dave/", ACLRead|ACLWrite); err != nil {
		t.Fatal(err)
	}
	perms, pfx, err := env.ACLRoleGet("tenant_dave")
	if err != nil {
		t.Fatal(err)
	}
	if perms != ACLRead|ACLWrite || pfx != "dave/" {
		t.Fatalf("role_get perms=%#x pfx=%q", perms, pfx)
	}
	if err := env.ACLRoleAssign("eve", "writer"); err != nil {
		t.Fatal(err)
	}
	if err := env.ACLRoleAssign("dave", "tenant_dave"); err != nil {
		t.Fatal(err)
	}
	eff, err := env.ACLEffective("eve")
	if err != nil {
		t.Fatal(err)
	}
	if eff&(ACLRead|ACLWrite) != ACLRead|ACLWrite {
		t.Fatalf("eve eff %#x", eff)
	}
	if err := env.SetPrincipal("eve"); err != nil {
		t.Fatal(err)
	}
	if err := env.Put("kv", []byte("anywhere"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := env.SetPrincipal("dave"); err != nil {
		t.Fatal(err)
	}
	if err := env.Put("kv", []byte("eve/x"), []byte("n")); err == nil {
		t.Fatal("dave should be denied outside prefix")
	}
	if err := env.Put("kv", []byte("dave/inbox"), []byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := env.SetPrincipal("alice"); err != nil {
		t.Fatal(err)
	}
	if err := env.ACLRoleUnassign("dave", "tenant_dave"); err != nil {
		t.Fatal(err)
	}
	if err := env.SetPrincipal("dave"); err != nil {
		t.Fatal(err)
	}
	if err := env.Put("kv", []byte("dave/z"), []byte("n")); err == nil {
		t.Fatal("dave should be denied after unassign")
	}
}
