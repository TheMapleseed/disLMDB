.. DisLMDB project README (reStructuredText).
.. The Howard Chu / LMDB tribute is included first so it leads the document.

.. include:: TRIBUTE_HOWARD_CHU.rst

----

DisLMDB: Distributed Lightning Memory-Mapped Database
=====================================================

DisLMDB extends `LMDB <https://symas.com/lmdb/>`_ with multi-node replication:
Raft or Enhanced-PBFT consensus, TCP/UDP/BOTH/QUIC transports, mTLS 1.3, and
layered crypto (transport HMAC/AEAD + optional mTLS; PBFT digests/MACs via
Time-Variant BLAKE3). Storage remains LMDB’s mmap’d B+tree.

**Status:** Phases A–N of the product roadmap are **complete**. The C ABI, Rust
crate, Go module, admin CLI, e2e goldens, and soak gates are locked in.
Optional follow-ups (re-measure SLOs on new CI hosts, publish crate/module to
private registries, commit session work) are operational — not unfinished
product gaps. Tracked in `TODO.md <TODO.md>`_.

Proprietary software — The Mapleseed Inc. Commercial license required.

What works today
----------------

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Area
     - Status
   * - **Consensus**
     - Enhanced-PBFT and Raft (``DISLMDB_CONSENSUS_*``), joint-consensus
       membership, graceful leave
   * - **Voting**
     - First-class; ``DISLMDB_VOTING=off`` / ``enable_voting=false`` → learner
       (no campaign / no vote grant)
   * - **Transports**
     - TCP, UDP (DQGM v3), **BOTH**, **QUIC** (TLS 1.3 HS + 1-RTT DQGM; X.509
       CertificateVerify)
   * - **Crypto (transport)**
     - Cluster key HMAC + AEAD payload encryption; portable mTLS 1.3 via
       vendored Mbed TLS
   * - **Crypto (PBFT)**
     - Time-Variant BLAKE3 digests + keyed MACs bound to ``(view, sequence)`` —
       not used for connections or Raft
   * - **Topology**
     - Env: ``DISLMDB_REGION`` / ``LOCALITY`` / ``TOPOLOGY_MODE`` / secrets /
       ``MAX_PEERS``; persisted region + peer_topo; same-region dial preference
   * - **Topo modes**
     - ``mirror`` / ``shard`` / ``hybrid``; auto-forward puts/dels
       (``enable_auto_forward``); read proxy ``dislmdb_topo_get`` /
       ``forward_get``
   * - **Scale**
     - Heap-growable peer + connection tables; soft ``max_peers`` (0 =
       unlimited). Regional voters; voter HB vs learner AE lanes
   * - **Shard map**
     - ``dislmdb_shard_map_*`` + SMAP v2 (flags); longest-prefix owner lookup;
       ``dislmdb_topo_key_writable``
   * - **KV / txns**
     - Opaque ``MDB_val`` keys/values; multi-DBI atomic apply under one
       consensus oplog
   * - **Secondary indexes**
     - ``dislmdb_index_put`` / ``del`` / ``get`` / ``scan`` (app-owned index
       DBI; optional prefix + limit)
   * - **Versioned LWW**
     - ``dislmdb_put_versioned`` / ``get_versioned`` +
       ``DISLMDB_MIRROR_CLIENT_TIMESTAMP``
   * - **Bytecode**
     - Consensus-replicated (or SOLO) store/get; ``VERIFY`` (SHA-256 plaintext)
       + ``COMPRESS`` (zlib)
   * - **ACL**
     - Opt-in ``enable_acl``: principal grants + **prefix grants** + **RBAC
       roles** (global or prefix-scoped)
   * - **Metrics**
     - ``dislmdb_get_metrics`` + ``format_metrics`` + ``export_metrics_file`` /
       ``DISLMDB_METRICS_FILE`` (no embedded HTTP)
   * - **Admin CLI**
     - ``dislmdb_admin`` — offline metrics/checkpoint/sync/leader; live
       ``cat-metrics``
   * - **Ops status**
     - ``dislmdb_consensus_get_operation_status`` / ``get_last_op_id`` via local
       oplog ring
   * - **Bindings**
     - C ABI (``bindings/ABI.kdl``), Rust crate (``bindings/rust``), Go cgo
       module (``bindings/go``)
   * - **Discovery**
     - HELLO/JOIN mesh engage before Raft elections
   * - **Test lanes**
     - Sandbox / unit / rig / integration / e2e (01–06) / orb / stress / QUIC
       soak / SLO baseline

Durability (honest)
-------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - What
     - Durable?
   * - User KV / LMDB pages
     - **Yes** — mmap + commit / ``dislmdb_force_sync`` / checkpoint
   * - Meta (view, replicas, shard map, region, ACL/RBAC tables)
     - **Yes** when ``persist_state``
   * - Optional cluster key
     - Meta DBI only if ``persist_cluster_key``
   * - Raft log / hard state
     - **Yes** when ``persist_state`` — ``__dislmdb_raft__`` WAL + snapshot
       compact
   * - PBFT view/seq
     - **Yes** when ``persist_state`` (meta DBI)
   * - Network outbox / DQGM counters
     - RAM

Local ACID properties of LMDB still apply per node. Cross-node linearizability
depends on the consensus path completing before the client sees success.

So: **data is not “all RAM”** — LMDB is disk-backed mmap; Raft durable state
lives in ``__dislmdb_raft__``. “Cooldown to disk” ≈ sync interval + checkpoint +
WAL sync policy.

Language bindings
-----------------

All three surfaces consume the same C ABI (`bindings/ABI.kdl <bindings/ABI.kdl>`_).
``make pc`` writes ``build/dislmdb.pc`` for pkg-config consumers.

.. list-table::
   :header-rows: 1
   :widths: 18 32 50

   * - Binding
     - Path
     - How to build / test
   * - **C**
     - ``include/dislmdb.h`` + ``libdislmdb``
     - ``make lib``
   * - **Rust crate**
     - `bindings/rust <bindings/rust>`_ (edition 2024)
     - ``make rust-bindings`` after ``make lib``
   * - **Go module**
     - `bindings/go <bindings/go>`_ (cgo)
     - ``make go-bindings`` after ``make lib`` (soft-skips if ``go`` missing)

Both high-level bindings link the **native** shared library (not pure Rust /
pure Go). Build ``libdislmdb`` first; rpath is wired for local ``build/lib``.

Rust (crate)
~~~~~~~~~~~~

.. code-block:: rust

   use dislmdb::{Env, OpenOptions, ACL_READ, ACL_WRITE};

   let env = Env::open_with(path, OpenOptions { enable_acl: true, maxdbs: 8 })?;
   env.set_principal("alice")?;
   env.acl_grant_all("alice")?;
   env.index_put("entities", "idx_name", b"u1", b"alice", b"alice")?;
   let (pk, pv) = env.index_get("entities", "idx_name", b"alice")?.unwrap();
   let rows = env.index_scan("entities", "idx_name", Some(b"a"), 0)?;
   env.acl_role_define("writer", None, ACL_READ | ACL_WRITE)?;
   env.acl_role_assign("eve", "writer")?;

Go (module)
~~~~~~~~~~~

.. code-block:: go

   import "github.com/mapleseed/dislmdb"

   env, err := dislmdb.OpenWith(path, dislmdb.OpenOptions{EnableACL: true, MaxDBs: 8})
   _ = env.SetPrincipal("alice")
   _ = env.ACLGrantAll("alice")
   _ = env.IndexPut("entities", "idx_name", []byte("u1"), []byte("alice"), []byte("alice"))
   pk, pv, _ := env.IndexGet("entities", "idx_name", []byte("alice"))
   rows, _ := env.IndexScan("entities", "idx_name", []byte("a"), 0)
   _ = env.ACLRoleDefine("writer", "", dislmdb.ACLRead|dislmdb.ACLWrite)

Requirements
------------

- C23 compiler (GCC 13+ or Clang 16+)
- Vendored Mbed TLS (``third_party/mbedtls``) for mTLS 1.3
- OpenSSL *libcrypto* (non-Apple) or Apple CommonCrypto
- ``uuid`` on Linux; POSIX OS
- Optional: Rust toolchain (edition 2024) for ``make rust-bindings``
- Optional: Go 1.22+ for ``make go-bindings``
- Makefile primary; CMake 3.16+ optional

Build & test
------------

.. code-block:: bash

   make                 # build + sandbox-safe suite
   make lib             # libdislmdb shared library
   make tools           # dislmdb_admin
   make check-sandbox   # unit + rigs (no LMDB mmap — agent/sandbox safe)
   make check-integration
   make check-orb       # Docker/OrbStack
   make check-stress    # soak (incl. QUIC ×20)
   make check-quic-soak
   make measure-slos
   make check           # sandbox + unit + integration (+ e2e)
   make rust-bindings
   make go-bindings     # soft-skip if go absent
   make pc              # build/dislmdb.pc

.. list-table::
   :header-rows: 1
   :widths: 18 28 54

   * - Layer
     - Location
     - Role
   * - Unit
     - ``tests/unit/``
     - Raft, crypto, metrics format, transport
   * - Rig
     - ``tests/rig/``
     - In-memory multi-node / fault (no LMDB mmap)
   * - Integration
     - ``tests/integration/``
     - LMDB cluster, mTLS, matrix, topo, ACL/RBAC, indexes, geo
   * - Orb
     - ``tests/orb/``
     - Container join / shard
   * - E2E
     - ``tests/e2e/``
     - Scenario scripts vs golden outputs (01–06)
   * - Stress / SLO
     - ``make check-stress``, ``measure-slos``, ``check-quic-soak``
     - Soak gates — see ``docs/soak_slos.kdl``

Agent sandboxes block LMDB ``mmap`` — use ``check-sandbox`` there; run
``check-integration`` on a normal host shell.

E2E scenarios
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Scenario
     - Covers
   * - ``01_basic_kv``
     - Put/get/del, checkpoint, metrics, reopen + cluster key
   * - ``02_bytecode``
     - Store/get, compress opts, persist across reopen
   * - ``03_consensus_apis``
     - Checkpoint, state transfer, sync
   * - ``04_acl_topo``
     - ACL grant/deny, region/locality/topo/voting, reopen
   * - ``05_index_versioned_acl``
     - Index put, versioned LWW reject, prefix ACL
   * - ``06_index_query_rbac``
     - ``INDEX_GET`` / ``INDEX_SCAN``, RBAC roles assign/unassign

.. code-block:: bash

   make e2e
   # or: ./tests/e2e/run_e2e.sh build/bin/e2e_runner

Quick start (solo)
------------------

.. code-block:: c

   #include <dislmdb.h>

   int main(void) {
       DISLMDB_env *env = NULL;
       DISLMDB_env_config config;
       dislmdb_env_config_init(&config);
       config.path = "./testdb";
       config.mapsize = 10 * 1024 * 1024;
       config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;

       if (dislmdb_env_create(&env) || dislmdb_env_open(env, &config)) {
           return 1;
       }

       DISLMDB_txn *txn = NULL;
       if (dislmdb_txn_begin(env, NULL, 0, &txn)) {
           dislmdb_env_close(env);
           return 1;
       }
       MDB_dbi dbi;
       if (dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi)) {
           dislmdb_txn_abort(txn);
           dislmdb_env_close(env);
           return 1;
       }
       MDB_val k = {.mv_size = 5, .mv_data = "hello"};
       MDB_val v = {.mv_size = 5, .mv_data = "world"};
       dislmdb_put(txn, dbi, &k, &v, 0);
       dislmdb_txn_commit(txn);

       DISLMDB_metrics m;
       char buf[4096];
       size_t n = 0;
       dislmdb_get_metrics(env, &m);
       dislmdb_format_metrics(&m, buf, sizeof(buf), &n);
       /* ship buf to your scrape endpoint / log */

       dislmdb_env_close(env);
       return 0;
   }

Multi-node deployments **must** set a shared cluster key
(``dislmdb_set_cluster_key`` / ``network.has_cluster_key``) or open fails
closed. Prefer Raft for crashy LANs; PBFT when Byzantine tolerance matters. See
``examples/``.

Application guide (keys, UUIDs, transactions)
---------------------------------------------

Normative conventions live in `docs/kv_and_txn.kdl <docs/kv_and_txn.kdl>`_.
Short form:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Topic
     - Rule
   * - **Keys/values**
     - Opaque bytes (``MDB_val``). Binary UUIDv7 (16 bytes) is fine and sorts
       by time.
   * - **Shard prefixes**
     - NUL-terminated C strings (longest-prefix match). Do **not** use raw
       16-byte UUIDs as ``key_prefix``; use ``user/`` / ``evt/`` and put the
       UUID in the key body.
   * - **Multi-key / multi-DBI**
     - One ``dislmdb_txn`` → one consensus oplog → one LMDB apply txn.
       Puts/dels across named DBIs in that txn are applied atomically.
   * - **Secondary indexes**
     - App-owned DBI via ``index_put`` / ``index_del`` / ``index_get`` /
       ``index_scan``.
   * - **Versioned LWW**
     - ``dislmdb_put_versioned`` / ``dislmdb_get_versioned`` +
       ``DISLMDB_MIRROR_CLIENT_TIMESTAMP`` (env
       ``DISLMDB_MIRROR_CONFLICT=client_timestamp|lww``).
   * - **ACL / RBAC**
     - Principal grants, prefix grants, roles (global or prefix-scoped). See
       ``docs/acl.kdl``.
   * - **Auto-forward**
     - Only when the txn has no prior local pending ops — no mixed
       local+forward batch.
   * - **Success**
     - Raft/PBFT: client sees success after consensus commit (staging aborted;
       durable via apply). SOLO: local LMDB commit.

IT lock-in: ``test_multikey_txn``, ``test_index_versioned``,
``test_index_query``, ``test_acl``.

Secondary indexes
~~~~~~~~~~~~~~~~~

.. code-block:: c

   /* One txn: primary row + secondary → primary key entry */
   dislmdb_index_put(txn, primary_dbi, index_dbi, &pkey, &pval, &skey, 0);

   /* Lookup */
   MDB_val got_pk, got_pv;
   dislmdb_index_get(txn, primary_dbi, index_dbi, &skey, &got_pk, &got_pv);

   /* Scan: optional start, byte-prefix filter, limit (0 = unlimited), callback */
   dislmdb_index_scan(txn, primary_dbi, index_dbi, NULL, &prefix, 0, cb, user);

Versioned values (LWW)
~~~~~~~~~~~~~~~~~~~~~~

Payload on disk is ``BE-u64 version || data``. A put with ``version <=``
existing is rejected locally (``DISLMDB_ERR_OPERATION_REJECTED``) before
consensus when using the client-timestamp mirror policy.

.. code-block:: c

   dislmdb_put_versioned(txn, dbi, &key, &val, 0, 100);
   uint64_t ver = 0;
   char buf[256];
   size_t cap = sizeof(buf);
   dislmdb_get_versioned(txn, dbi, &key, &ver, buf, &cap);

ACL & RBAC
----------

Opt-in via ``DISLMDB_env_config.enable_acl`` (off by default). Independent of
transport crypto / mTLS / QUIC PKI. Normative doc:
`docs/acl.kdl <docs/acl.kdl>`_.

.. list-table::
   :header-rows: 1
   :widths: 18 36 46

   * - Mechanism
     - API
     - Notes
   * - Principal
     - ``dislmdb_acl_set_principal``
     - Current caller for gated ops
   * - Global grant
     - ``acl_grant`` / ``revoke`` / ``get``
     - ``READ`` / ``WRITE`` / ``ADMIN`` / ``ALL``
   * - Prefix grant
     - ``acl_grant_prefix`` / ``revoke_prefix`` / ``get_prefix``
     - Longest-match; READ/WRITE only
   * - Roles
     - ``acl_role_define`` / ``undefine`` / ``get``
     - Empty prefix = global (may include ADMIN); non-empty = READ/WRITE scoped
   * - Membership
     - ``acl_role_assign`` / ``unassign``
     - Requires ADMIN after bootstrap
   * - Effective
     - ``acl_effective``
     - Direct grant ∪ empty-prefix role bits

Bootstrap: first grant with empty grant table establishes the initial admin.
Prefix-scoped role bits are key-dependent (same longest-match rules as prefix
grants). Tables persist under meta keys ``acl_roles`` / ``acl_role_members``
when ``persist_state`` is on.

Ops & geo (playbooks)
---------------------

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Doc
     - Contents
   * - `docs/ops_backup.kdl <docs/ops_backup.kdl>`_
     - Checkpoint/sync, cold-copy of ``data.mdb``, restore, metrics sidecar,
       soak lanes
   * - `docs/acl.kdl <docs/acl.kdl>`_
     - Global + prefix ACL + RBAC
   * - `docs/kv_and_txn.kdl <docs/kv_and_txn.kdl>`_
     - Keys, UUIDs, multi-DBI ACID, indexes, versioned LWW
   * - `docs/geo_playbook.kdl <docs/geo_playbook.kdl>`_
     - Hub vs leaf voting, mirror/shard/hybrid, env knobs, failure domains
   * - `docs/soak_slos.kdl <docs/soak_slos.kdl>`_
     - CI soak gates; ``make measure-slos`` / ``check-quic-soak``; measured
       p50/p99

Admin CLI
~~~~~~~~~

.. code-block:: bash

   make tools
   # Offline (exclusive LMDB lock — stop the node first):
   build/bin/dislmdb_admin --path ./data metrics|checkpoint|sync|leader|status|export-metrics
   # Live scrape (no LMDB lock):
   build/bin/dislmdb_admin cat-metrics /run/dislmdb.prom

Set ``DISLMDB_METRICS_FILE`` on the running node; sync/checkpoint refresh the
file via ``dislmdb_export_metrics_file``.

**Backup (short):** quiesce → ``dislmdb_checkpoint`` + ``dislmdb_force_sync`` →
close → copy the env directory. Restore into an empty/stopped path with the
same cluster key; prefer catch-up from a live leader if the copy may be stale.
Outbox/DQGM counters are RAM-only.

**Geo (short):** small same-region voter hubs (``DISLMDB_VOTING=on``); edges as
learners (``off``); choose ``mirror``/``shard``/``hybrid`` before load;
separate region vs cross-region secrets.

Topology env (large / regional fleets)
--------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Variable
     - Role
   * - ``DISLMDB_VOTING``
     - ``on``/``off`` — hubs vote; edges can be learners
   * - ``DISLMDB_REGION`` / ``DISLMDB_LOCALITY``
     - Affinity for dial preference + persist
   * - ``DISLMDB_REGION_SECRET`` / ``DISLMDB_CROSS_REGION_SECRET``
     - Intra- / inter-region key material
   * - ``DISLMDB_TOPOLOGY_MODE``
     - ``mirror`` (default) \| ``shard`` \| ``hybrid`` — gates writes + Raft
       peer role
   * - ``DISLMDB_MIRROR_CONFLICT``
     - ``last_write`` \| ``region_priority`` \| ``client_timestamp`` / ``lww``
   * - ``DISLMDB_MIRROR_PRIMARY_REGION``
     - Allowed writer region under ``REGION_PRIORITY``
   * - ``DISLMDB_MAX_PEERS``
     - Soft membership cap (``0`` = unlimited)
   * - ``DISLMDB_RTT_BUDGET_MS``
     - Soft RTT budget (admit policy evolving)
   * - ``DISLMDB_SEED_REGIONAL``
     - Comma-separated ``host:port`` seeds
   * - ``DISLMDB_METRICS_FILE``
     - Path refreshed on sync/checkpoint for live scrape
   * - ``DISLMDB_QUIC_SOAK_ROUNDS``
     - Override for ``make check-quic-soak``

Secret rotation (no full outage)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Plane keys are process-local (``DISLMDB_REGION_SECRET`` /
``DISLMDB_CROSS_REGION_SECRET`` or ``dislmdb_network_set_plane_keys``). Rotate
without a cluster restart by rolling nodes:

1. Deploy the **new** key as an additional candidate on receivers first (set
   both old and new via a short dual-key window — today the cross plane is a
   single key, so overlap means briefly configuring the new key cluster-wide
   before dropping the old).
2. Flip senders to the new key (``set_plane_keys`` / env + process reload)
   region-by-region.
3. Remove the old key after every peer has advanced.

Mismatched cross-region keys fail closed (``plane_auth_fail``); intra-region
traffic keeps using the region/cluster key. Prefer rotating **cross** keys
before **region** keys so local quorum is undisturbed.

``dislmdb_topo_map_publish`` replicates peer endpoints after join;
``dislmdb_topo_resolve_owner`` lets apps redirect shard writes when this node
is not the owner.

Architecture
------------

1. **Core API** — LMDB transactions + distributed helpers (``include/dislmdb.h``)
2. **Consensus** — ``Enhanced-Raft-mechanism/`` or ``Enhanced-PBFT-mechanism/``
   via adapters
3. **Network** — framed messages, DQGM UDP, outbox, mTLS / QUIC
   (``src/network/``)
4. **Storage** — LMDB mmap + meta DBI persist (``src/utils/dislmdb_persist.c``)
5. **ACL / indexes / versioned** — ``src/utils/dislmdb_acl.c``, ``dislmdb_ops.c``
6. **Bindings** — ``bindings/ABI.kdl``, ``bindings/rust``, ``bindings/go``
7. **Tools / e2e** — ``tools/dislmdb_admin.c``, ``tests/e2e/``

.. code-block:: text

   ┌─────────────┐   ┌──────────────┐   ┌─────────────┐
   │ Rust / Go   │──▶│ C ABI        │──▶│ Consensus   │
   │ bindings    │   │ dislmdb.h    │   │ Raft / PBFT │
   └─────────────┘   └──────┬───────┘   └──────┬──────┘
                            │                  │
                            ▼                  ▼
                     ┌──────────────┐   ┌─────────────┐
                     │ LMDB mmap    │   │ Network     │
                     │ + meta persist│   │ TCP/UDP/QUIC│
                     └──────────────┘   └─────────────┘

Crypto layers (what each piece owns)
------------------------------------

DisLMDB uses **two separate crypto planes**. Mixing them up is a common misread
of this repo. Together they are the intended resistance to **temporal / timing
attack vectors**: TVB3 removes fixed-time digest domains; transport HMAC + AEAD
(and optional mTLS) encrypt and authenticate the wire so plaintext and stable
MAC material are not exposed for remote timing aggregation.

.. list-table::
   :header-rows: 1
   :widths: 18 22 30 30

   * - Layer
     - Mechanism
     - Owns
     - Does **not** own
   * - **Transport**
     - Cluster-key HMAC + AEAD; optional mTLS 1.3
     - Peer dial/admit, framed packets, RTT/HELLO path authenticity; ciphertext
       + tag verify (``dislmdb_crypto_secure_eq``)
     - PBFT digests, Raft log hashes
   * - **Enhanced-PBFT**
     - Time-Variant BLAKE3 (TVB3)
     - Request digests + PBFT wire ``auth`` MACs (slot-bound; MAC verify is
       fixed-length XOR fold)
     - Sockets, mTLS, Raft AppendEntries / RequestVote

Prefer Raft for crashy LANs; PBFT when Byzantine tolerance matters. TVB3 only
applies on the PBFT path.

Time-Variant BLAKE3 (Enhanced-PBFT)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TVB3 is the Enhanced-PBFT digest/MAC primitive (C port under
``Enhanced-PBFT-mechanism/``, aligned with
`Time-VariantBlake3 <https://github.com/TheMapleseed/Time-VariantBlake3>`_).
The paper’s compression binding is
:math:`G'(h,m,t)=G(h\oplus IV(t), m, t)`: digests are **not** a fixed,
time-invariant fingerprint of the payload alone.

**Consensus profile (what DisLMDB runs).** For replica agreement, “time” is
**not** wall-clock: every replica derives a deterministic IV from the consensus
step ``(view, sequence)``. Honest nodes with the same ``(view, seq)`` produce
the same digest and MAC; safety does not require NTP. Each new slot still gets
a distinct IV (paper invariant: distinct :math:`t` ⇒ distinct :math:`IV` with
overwhelming probability).

**Purpose 1 — Resist temporal / timing attack vectors (with transport
encryption).** Classic ``H(m)`` is stable across time and slots, which enables
precomputation against a single IV, cross-time digest reuse, and aggregation of
repeated identical hash domains (including remote timing measurements over a
fixed computation). TVB3’s time-differential IV is intended to break that
stability per consensus step. On the wire, cluster-key **AEAD + HMAC** (and
optional **mTLS 1.3**) add encryption and authenticated framing so observers do
not get cleartext payloads or naked digest bytes to time against; tag checks
use constant-time-style compares (``secure_eq`` / TVB3 MAC verify). **Layered
posture:** TVB3 for time-variant digests/MACs; transport crypto for encrypted,
authenticated channels. Deploy multi-node with a cluster key (required) and
prefer mTLS when the threat model includes network adversaries.

**Purpose 2 — Step-bound request digests.** On Pre-prepare (and inbound
checks)::

   digest = TVB3_hash(view, sequence, payload)

Implementation: BLAKE3 chaining value starts as ``BLAKE3_IV ⊕ IV(view,seq)``,
then the payload is hashed (``tvb3_hash_payload`` / ``security_manager``).
Effects:

- The same payload at ``(v, n)`` hashes differently than at ``(v′, n′)``.
- Quorum certificates cannot be slid across sequence slots without failing
  digest checks.
- All honest replicas still agree, because the IV is a pure function of
  ``(view, seq)``.

``epdft.c`` drops a Pre-prepare when the recomputed TVB3 digest does not match
the message.

**Purpose 3 — Step-bound wire MACs (cluster key).** When a cluster key is
installed, every PBFT message carries an ``auth`` tag: keyed BLAKE3 whose
key-schedule/CV is XOR’d with the same TV-IV, over a canonical encoding of
``(type, view, seq, digest, from, last_stable, data)``. Verify rejects
missing/wrong MACs once a key is present. A valid MAC for one PBFT phase/slot
does not authorize another.

**Purpose 4 — Spec alignment.** Digests and ``auth`` follow the Enhanced-PBFT /
TV-BLAKE3 construction, not ad-hoc SHA-256 of the payload. Raft intentionally
skips this path and uses ordinary Raft framing plus the **transport** crypto
layer.

**Out of scope for TVB3 alone:** dialing peers, connection admit, RTT budgets,
mTLS handshakes, encrypting the LMDB store, or Raft AE/RV — those sit in the
transport / storage planes (encryption and mTLS are what close the remote
timing/observation gap on the wire).

In one line: TVB3 + transport HMAC/AEAD (and optional mTLS) make PBFT
digests/MACs **slot-bound and time-variant**, and keep the wire **encrypted and
authenticated**, so fixed-time digest and remote timing/aggregation vectors are
out of the intended threat surface—while digests stay deterministic across the
cluster.

Details and file map:
`Enhanced-PBFT-mechanism/README.md <Enhanced-PBFT-mechanism/README.md>`_.
Spec:
`Time-VariantBlake3 <https://github.com/TheMapleseed/Time-VariantBlake3>`_.

Metrics
-------

.. code-block:: c

   DISLMDB_metrics m;
   dislmdb_get_metrics(env, &m);
   /* m.raft_term, m.dqgm_packets_rx, m.outbox_dropped, … */

   char text[8192];
   size_t n = 0;
   dislmdb_format_metrics(&m, text, sizeof(text), &n);

   /* Live file for a sidecar scrape (also refreshed on sync/checkpoint): */
   setenv("DISLMDB_METRICS_FILE", "/run/dislmdb.prom", 1);
   dislmdb_export_metrics_file(env, NULL); /* NULL → env path */

No embedded scrape HTTP server — expose ``text`` from your process supervisor
or sidecar (``dislmdb_admin cat-metrics``).

Package layout (high level)
---------------------------

.. code-block:: text

   include/           Public headers (dislmdb.h, errors, network, consensus, crypto, quic)
   src/               Core env, network, ops, ACL, persist, LMDB
   Enhanced-Raft-mechanism/
   Enhanced-PBFT-mechanism/
   bindings/          ABI.kdl, rust/, go/
   docs/              *.kdl playbooks (kv, acl, geo, backup, soak)
   tools/             dislmdb_admin
   examples/          basic / distributed / bytecode
   tests/             unit, rig, integration, e2e, orb
   third_party/       mbedtls

Attribution
-----------

The Howard Chu / LMDB tribute is included at the **top** of this README
(`TRIBUTE_HOWARD_CHU.rst <TRIBUTE_HOWARD_CHU.rst>`_). If you ship or cite
DisLMDB, please mention LMDB and Howard Chu as well.

Roadmap
-------

Tracked in `TODO.md <TODO.md>`_: **Phases A–N complete.**

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Phase
     - Focus
   * - A–E
     - Scale / region / topology
   * - F
     - Raft WAL / FSM
   * - G
     - I/O + QUIC stack
   * - H
     - Compress / ACL / bindings / metrics
   * - I
     - Harden
   * - J
     - System-wide tests
   * - K
     - Product gaps (indexes, versioned LWW, QUIC soak, geo, ACL prefix, ops)
   * - L
     - CI lock-in, metrics file, Go sketch, ``index_get``/``scan``, RBAC
   * - M
     - e2e 06 + Rust query/RBAC surface
   * - N
     - Go query/RBAC parity

Not product gaps: re-run ``make measure-slos`` on new hardware; private registry
publish of Rust/Go packages; git commit/push when you ask.

License
-------

Commercial proprietary — The Mapleseed Inc. Unauthorized use prohibited.

Copyright 2025–2026 David Harmon, The Mapleseed Inc.

Contributing
------------

CLA required. Contact us before submitting contributions.
