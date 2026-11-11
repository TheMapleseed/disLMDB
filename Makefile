# DisLMDB Makefile — portable POSIX build (no platform-localized TLS stacks).
# mTLS 1.3: vendored Mbed TLS in third_party/mbedtls (same on every host).
# Hash/HMAC: Apple CommonCrypto on Darwin, OpenSSL libcrypto elsewhere.
# `make` / `make all` builds libraries, examples, and runs the full test suite.

CC       ?= clang
STD      ?= -std=c23
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic $(STD) -fPIC
# Auto header deps (-MMD/-MP) so DISLMDB_env / API layout edits rebuild .o files
DEPFLAGS ?= -MMD -MP
CPPFLAGS += -Iinclude -Isrc -IEnhanced-PBFT-mechanism -IEnhanced-Raft-mechanism \
            -Ithird_party/mbedtls/include -DDISLMDB_USE_COMMONCRYPTO
LDFLAGS  ?=
LIBS     ?= -lpthread -lz

MBEDTLS_DIR := third_party/mbedtls
MBEDTLS_LIBDIR := $(MBEDTLS_DIR)/library
MBEDTLS_LIBS := \
  $(MBEDTLS_LIBDIR)/libmbedtls.a \
  $(MBEDTLS_LIBDIR)/libmbedx509.a \
  $(MBEDTLS_LIBDIR)/libmbedcrypto.a

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LIBS += -framework Security
  RPATH := -Wl,-rpath,@loader_path/../lib
  SHARED_EXT := dylib
  SHARED_FLAGS := -shared -install_name @rpath/libdislmdb.dylib
else
  LIBS += -luuid -lcrypto
  CPPFLAGS := $(filter-out -DDISLMDB_USE_COMMONCRYPTO,$(CPPFLAGS)) -DDISLMDB_USE_OPENSSL
  RPATH := -Wl,-rpath,'$$ORIGIN/../lib'
  SHARED_EXT := so
  SHARED_FLAGS := -shared -Wl,-soname,libdislmdb.so
endif

BUILD    := build
LIBDIR   := $(BUILD)/lib
BINDIR   := $(BUILD)/bin
OBJDIR   := $(BUILD)/obj
LMDB_SRCS := src/mdb.c src/midl.c
DISLMDB_SRCS := \
  src/dislmdb.c \
  src/utils/dislmdb_utils.c \
  src/utils/dislmdb_crypto.c \
  src/utils/dislmdb_ops.c \
  src/utils/dislmdb_acl.c \
  src/utils/dislmdb_persist.c \
  src/utils/dislmdb_shard.c \
  src/utils/dislmdb_topo.c \
  src/network/dislmdb_network.c \
  src/network/dislmdb_mtls.c \
  src/network/dislmdb_quic.c \
  src/network/dislmdb_quic_tls.c \
  src/network/dislmdb_iouring.c \
  src/consensus/dislmdb_consensus.c \
  src/consensus/pbft_adapter.c \
  src/consensus/raft_adapter.c \
  src/consensus/raft_wal.c \
  Enhanced-PBFT-mechanism/epdft.c \
  Enhanced-PBFT-mechanism/messaging.c \
  Enhanced-PBFT-mechanism/security_manager.c \
  Enhanced-PBFT-mechanism/blake3_ref.c \
  Enhanced-PBFT-mechanism/time_variant_blake3.c \
  Enhanced-Raft-mechanism/raft.c

LMDB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LMDB_SRCS))
DISLMDB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(DISLMDB_SRCS))

# Sandbox-safe unit tests (no LMDB mmap)
UNIT_SANDBOX_TESTS := \
  $(BINDIR)/test_tvb3 \
  $(BINDIR)/test_raft \
  $(BINDIR)/test_raft_membership \
  $(BINDIR)/test_raft_peer_growth \
  $(BINDIR)/test_metrics_format \
  $(BINDIR)/test_mtls \
  $(BINDIR)/test_transport_adapt \
  $(BINDIR)/test_quic_substrate

# Needs libdislmdb but no env mmap in the happy path
UNIT_LIB_TESTS := \
  $(BINDIR)/test_crypto

UNIT_TESTS := $(UNIT_SANDBOX_TESTS) $(UNIT_LIB_TESTS)

# In-memory / TCP rigs — no LMDB env open (safe inside agent sandbox)
RIG_TESTS := \
  $(BINDIR)/test_mtls_tcp_rig \
  $(BINDIR)/test_raft_bus_rig \
  $(BINDIR)/test_cluster_rig

INTEGRATION_TESTS := \
  $(BINDIR)/test_ops_persist \
  $(BINDIR)/test_acl \
  $(BINDIR)/test_system_surface \
  $(BINDIR)/test_raft_learner \
  $(BINDIR)/test_multikey_txn \
  $(BINDIR)/test_index_versioned \
  $(BINDIR)/test_index_query \
  $(BINDIR)/test_connect_churn_quic \
  $(BINDIR)/test_quic_pki_reject \
  $(BINDIR)/test_geo_regions \
  $(BINDIR)/test_slo_baseline \
  $(BINDIR)/test_op_status \
  $(BINDIR)/test_membership \
  $(BINDIR)/test_shard_map \
  $(BINDIR)/test_multinode \
  $(BINDIR)/test_udp \
  $(BINDIR)/test_mixed \
  $(BINDIR)/test_mtls_cluster \
  $(BINDIR)/test_raft_udp \
  $(BINDIR)/test_raft_quic \
  $(BINDIR)/test_raft_tcp \
  $(BINDIR)/test_raft_both \
  $(BINDIR)/test_raft_mtls \
  $(BINDIR)/test_raft_mtls_tcp \
  $(BINDIR)/test_raft_matrix \
  $(BINDIR)/test_connect_churn \
  $(BINDIR)/test_auth_reject \
  $(BINDIR)/test_topo_env \
  $(BINDIR)/test_topo_modes \
  $(BINDIR)/test_topo_forward \
  $(BINDIR)/test_topo_plane \
  $(BINDIR)/test_raft_wal \
  $(BINDIR)/test_raft_wal_chaos \
  $(BINDIR)/test_raft_fault \
  $(BINDIR)/test_raft_stage \
  $(BINDIR)/test_raft_membership_it \
  $(BINDIR)/test_raft_leave \
  $(BINDIR)/test_pbft_viewchange \
  $(BINDIR)/test_fault_tolerance

BASIC_TEST := $(BINDIR)/dislmdb_test
E2E_RUNNER := $(BINDIR)/e2e_runner

.PHONY: all dirs lib mbedtls examples test-bins check check-sandbox check-integration \
        check-orb check-stress orb-bins unit unit-sandbox rig integration e2e test \
        clean smoke-example pc rust-bindings

# Default: build + sandbox-safe suite (works under Cursor agent sandbox)
all: lib examples test-bins check-sandbox

dirs:
	@mkdir -p $(LIBDIR) $(BINDIR) \
	  $(OBJDIR)/src/utils $(OBJDIR)/src/network $(OBJDIR)/src/consensus \
	  $(OBJDIR)/Enhanced-PBFT-mechanism $(OBJDIR)/Enhanced-Raft-mechanism \
	  $(BUILD)/e2e_work

# Portable TLS 1.3 stack (identical on every host)
mbedtls: $(MBEDTLS_LIBS)

$(MBEDTLS_LIBS):
	@test -d $(MBEDTLS_DIR)/library || { \
	  echo "error: missing $(MBEDTLS_DIR) — vendor Mbed TLS 3.6+ under third_party/mbedtls"; \
	  exit 1; }
	$(MAKE) -C $(MBEDTLS_LIBDIR) libmbedtls.a libmbedx509.a libmbedcrypto.a

$(OBJDIR)/src/mdb.o $(OBJDIR)/src/midl.o: CPPFLAGS += -w

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

# Generated by $(DEPFLAGS); keep next to objects under build/
DISLMDB_DEPS := $(DISLMDB_OBJS:.o=.d)
LMDB_DEPS := $(LMDB_OBJS:.o=.d)
-include $(DISLMDB_DEPS) $(LMDB_DEPS)

$(LIBDIR)/liblmdb.a: $(LMDB_OBJS) | dirs
	ar rcs $@ $^

$(LIBDIR)/libdislmdb.$(SHARED_EXT): $(DISLMDB_OBJS) $(LIBDIR)/liblmdb.a $(MBEDTLS_LIBS) | dirs
	$(CC) $(SHARED_FLAGS) -o $@ $(DISLMDB_OBJS) -L$(LIBDIR) -llmdb \
	  $(MBEDTLS_LIBS) $(LIBS) $(LDFLAGS)

lib: $(LIBDIR)/libdislmdb.$(SHARED_EXT)

examples: $(BINDIR)/basic_example $(BINDIR)/distributed_example $(BINDIR)/bytecode_example

tools: $(BINDIR)/dislmdb_admin

smoke-example: $(BINDIR)/distributed_example
	@chmod +x examples/run_distributed_smoke.sh
	@./examples/run_distributed_smoke.sh

$(BINDIR)/basic_example: examples/basic_example.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/distributed_example: examples/distributed_example.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/bytecode_example: examples/bytecode_example.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/dislmdb_admin: tools/dislmdb_admin.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

# --- Test binaries ----------------------------------------------------------

test-bins: $(BASIC_TEST) $(UNIT_TESTS) $(RIG_TESTS) $(INTEGRATION_TESTS) $(E2E_RUNNER)

$(BASIC_TEST): tests/dislmdb_test.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_crypto: tests/unit/test_crypto.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_tvb3: tests/unit/test_tvb3.c Enhanced-PBFT-mechanism/time_variant_blake3.c \
		Enhanced-PBFT-mechanism/blake3_ref.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_raft: tests/unit/test_raft.c Enhanced-Raft-mechanism/raft.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_raft_membership: tests/unit/test_raft_membership.c Enhanced-Raft-mechanism/raft.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_raft_peer_growth: tests/unit/test_raft_peer_growth.c Enhanced-Raft-mechanism/raft.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_metrics_format: tests/unit/test_metrics_format.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_mtls: tests/unit/test_mtls.c src/network/dislmdb_mtls.c $(MBEDTLS_LIBS) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_mtls.c src/network/dislmdb_mtls.c -o $@ \
	  $(MBEDTLS_LIBS) $(LIBS)

$(BINDIR)/test_transport_adapt: tests/unit/test_transport_adapt.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_quic_substrate: tests/unit/test_quic_substrate.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_mtls_tcp_rig: tests/rig/test_mtls_tcp_rig.c src/network/dislmdb_mtls.c $(MBEDTLS_LIBS) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/rig/test_mtls_tcp_rig.c src/network/dislmdb_mtls.c -o $@ \
	  $(MBEDTLS_LIBS) $(LIBS)

$(BINDIR)/test_raft_bus_rig: tests/rig/test_raft_bus_rig.c Enhanced-Raft-mechanism/raft.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_cluster_rig: tests/rig/test_cluster_rig.c tests/rig/cluster_rig.c \
		Enhanced-Raft-mechanism/raft.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Itests/rig $^ -o $@ $(LIBS)

$(BINDIR)/test_ops_persist: tests/integration/test_ops_persist.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_acl: tests/integration/test_acl.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_system_surface: tests/integration/test_system_surface.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_raft_learner: tests/integration/test_raft_learner.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_multikey_txn: tests/integration/test_multikey_txn.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_index_versioned: tests/integration/test_index_versioned.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_index_query: tests/integration/test_index_query.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_connect_churn_quic: tests/integration/test_connect_churn_quic.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_quic_pki_reject: tests/integration/test_quic_pki_reject.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_geo_regions: tests/integration/test_geo_regions.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_slo_baseline: tests/integration/test_slo_baseline.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_op_status: tests/integration/test_op_status.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_membership: tests/integration/test_membership.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_shard_map: tests/integration/test_shard_map.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_multinode: tests/integration/test_multinode.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_udp: tests/integration/test_udp.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_mixed: tests/integration/test_mixed.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_mtls_cluster: tests/integration/test_mtls_cluster.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_udp: tests/integration/test_raft_udp.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_quic: tests/integration/test_raft_quic.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_tcp: tests/integration/test_raft_tcp.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_both: tests/integration/test_raft_both.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_mtls: tests/integration/test_raft_mtls.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_mtls_tcp: tests/integration/test_raft_mtls_tcp.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_matrix: tests/integration/test_raft_matrix.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_connect_churn: tests/integration/test_connect_churn.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_auth_reject: tests/integration/test_auth_reject.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_topo_env: tests/integration/test_topo_env.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_topo_modes: tests/integration/test_topo_modes.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_topo_forward: tests/integration/test_topo_forward.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_topo_plane: tests/integration/test_topo_plane.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_wal: tests/integration/test_raft_wal.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_wal_chaos: tests/integration/test_raft_wal_chaos.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_fault: tests/integration/test_raft_fault.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_stage: tests/integration/test_raft_stage.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_membership_it: tests/integration/test_raft_membership.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_raft_leave: tests/integration/test_raft_leave.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_pbft_viewchange: tests/integration/test_pbft_viewchange.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(BINDIR)/test_fault_tolerance: tests/integration/test_fault_tolerance.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) \
	  -Wl,-rpath,$(abspath $(LIBDIR))

$(E2E_RUNNER): tests/e2e/e2e_runner.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

# --- Test execution ---------------------------------------------------------

unit-sandbox: $(UNIT_SANDBOX_TESTS)
	@echo ""
	@echo ">>>> Unit (sandbox-safe, no LMDB mmap)"
	@$(BINDIR)/test_tvb3
	@$(BINDIR)/test_raft
	@$(BINDIR)/test_raft_membership
	@$(BINDIR)/test_raft_peer_growth
	@cd $(BUILD) && ./bin/test_metrics_format
	@cd $(BUILD) && ./bin/test_mtls
	@cd $(BUILD) && ./bin/test_transport_adapt
	@cd $(BUILD) && ./bin/test_quic_substrate

rig: $(RIG_TESTS)
	@echo ""
	@echo ">>>> Rigs (mTLS TCP + Raft bus + multi-node cluster — no LMDB)"
	@cd $(BUILD) && ./bin/test_mtls_tcp_rig
	@cd $(BUILD) && ./bin/test_raft_bus_rig
	@cd $(BUILD) && ./bin/test_cluster_rig

# Agent / Cursor sandbox: no mmap required
check-sandbox: unit-sandbox rig
	@echo ""
	@echo "Sandbox-safe suites PASSED (use 'make check-integration' outside the sandbox)."

unit: unit-sandbox $(UNIT_LIB_TESTS)
	@echo ""
	@echo ">>>> Unit (lib-backed crypto)"
	@$(BINDIR)/test_crypto

integration: $(INTEGRATION_TESTS) $(BASIC_TEST)
	@echo ""
	@echo ">>>> Integration / basic tests (requires unsandboxed mmap)"
	@cd $(BINDIR) && ./dislmdb_test
	@cd $(BUILD) && ./bin/test_ops_persist
	@cd $(BUILD) && ./bin/test_acl
	@cd $(BUILD) && ./bin/test_system_surface
	@cd $(BUILD) && ./bin/test_op_status
	@cd $(BUILD) && ./bin/test_membership
	@cd $(BUILD) && ./bin/test_shard_map
	@cd $(BUILD) && ./bin/test_multinode
	@cd $(BUILD) && ./bin/test_udp
	@cd $(BUILD) && ./bin/test_mixed
	@cd $(BUILD) && ./bin/test_mtls_cluster
	@cd $(BUILD) && ./bin/test_raft_udp
	@cd $(BUILD) && ./bin/test_raft_quic
	@cd $(BUILD) && ./bin/test_raft_tcp
	@cd $(BUILD) && ./bin/test_raft_learner
	@cd $(BUILD) && ./bin/test_multikey_txn
	@cd $(BUILD) && ./bin/test_index_versioned
	@cd $(BUILD) && ./bin/test_index_query
	@cd $(BUILD) && ./bin/test_raft_both
	@cd $(BUILD) && ./bin/test_raft_mtls
	@cd $(BUILD) && ./bin/test_raft_mtls_tcp
	@cd $(BUILD) && ./bin/test_raft_matrix
	@cd $(BUILD) && ./bin/test_connect_churn
	@cd $(BUILD) && ./bin/test_connect_churn_quic
	@cd $(BUILD) && ./bin/test_auth_reject
	@cd $(BUILD) && ./bin/test_quic_pki_reject
	@cd $(BUILD) && ./bin/test_topo_env
	@cd $(BUILD) && ./bin/test_topo_modes
	@cd $(BUILD) && ./bin/test_topo_forward
	@cd $(BUILD) && ./bin/test_topo_plane
	@cd $(BUILD) && ./bin/test_geo_regions
	@cd $(BUILD) && ./bin/test_slo_baseline
	@cd $(BUILD) && ./bin/test_raft_wal
	@cd $(BUILD) && ./bin/test_raft_wal_chaos
	@cd $(BUILD) && ./bin/test_raft_fault
	@cd $(BUILD) && ./bin/test_raft_stage
	@cd $(BUILD) && ./bin/test_raft_membership_it
	@cd $(BUILD) && ./bin/test_raft_leave
	@cd $(BUILD) && ./bin/test_pbft_viewchange
	@cd $(BUILD) && ./bin/test_fault_tolerance

# Repeat flake-prone / matrix cells for soak confidence
check-stress: $(BINDIR)/test_raft_mtls $(BINDIR)/test_raft_matrix \
		$(BINDIR)/test_connect_churn $(BINDIR)/test_cluster_rig \
		$(BINDIR)/test_raft_quic
	@echo ""
	@echo ">>>> Stress (repeat flake-prone + matrix + churn + QUIC)"
	@fails=0; \
	for i in $$(seq 1 20); do \
	  $(BINDIR)/test_raft_mtls >/dev/null || { fails=$$((fails+1)); echo "raft_mtls fail $$i"; }; \
	done; \
	for i in $$(seq 1 20); do \
	  $(BINDIR)/test_raft_quic >/dev/null || { fails=$$((fails+1)); echo "raft_quic fail $$i"; }; \
	done; \
	$(BINDIR)/test_raft_matrix || fails=$$((fails+1)); \
	$(BINDIR)/test_connect_churn || fails=$$((fails+1)); \
	cd $(BUILD) && ./bin/test_cluster_rig || fails=$$((fails+1)); \
	if [ $$fails -ne 0 ]; then echo "STRESS FAILED ($$fails)"; exit 1; fi; \
	echo "Stress PASSED (20× raft_mtls + 20× raft_quic + matrix + connect_churn + cluster_rig)."

# Measure hub election + leaf catchup; prints p50/p99 for docs/soak_slos.kdl.
DISLMDB_SLO_ROUNDS ?= 10
measure-slos: $(BINDIR)/test_slo_baseline
	@echo ""
	@echo ">>>> SLO baseline (DISLMDB_SLO_ROUNDS=$(DISLMDB_SLO_ROUNDS))"
	@cd $(BUILD) && DISLMDB_SLO_ROUNDS=$(DISLMDB_SLO_ROUNDS) ./bin/test_slo_baseline

# Optional nightly QUIC long soak (minutes). Override rounds via DISLMDB_QUIC_SOAK_ROUNDS.
DISLMDB_QUIC_SOAK_ROUNDS ?= 30
check-quic-soak: $(BINDIR)/test_raft_quic $(BINDIR)/test_connect_churn_quic \
		$(BINDIR)/test_quic_pki_reject
	@echo ""
	@echo ">>>> QUIC long soak ($(DISLMDB_QUIC_SOAK_ROUNDS) rounds raft_quic + churn + pki)"
	@fails=0; \
	for i in $$(seq 1 $(DISLMDB_QUIC_SOAK_ROUNDS)); do \
	  $(BINDIR)/test_raft_quic >/dev/null || { fails=$$((fails+1)); echo "raft_quic fail $$i"; }; \
	  $(BINDIR)/test_connect_churn_quic >/dev/null || { fails=$$((fails+1)); echo "churn_quic fail $$i"; }; \
	done; \
	$(BINDIR)/test_quic_pki_reject >/dev/null || fails=$$((fails+1)); \
	if [ $$fails -ne 0 ]; then echo "QUIC SOAK FAILED ($$fails)"; exit 1; fi; \
	echo "QUIC soak PASSED ($(DISLMDB_QUIC_SOAK_ROUNDS)× raft_quic+churn + pki)."

e2e: $(E2E_RUNNER)
	@echo ""
	@echo ">>>> End-to-end scenarios (golden I/O)"
	@chmod +x tests/e2e/run_e2e.sh
	@./tests/e2e/run_e2e.sh $(E2E_RUNNER)

check-integration: integration e2e
	@echo ""
	@echo "Integration + e2e PASSED."

# OrbStack / Docker: real LMDB + join/spawn/shard (requires docker)
orb-bins: $(BINDIR)/orb_node_agent $(BINDIR)/orb_ctl

$(BINDIR)/orb_node_agent: tests/orb/node_agent.c $(LIBDIR)/libdislmdb.$(SHARED_EXT) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/orb_ctl: tests/orb/orb_ctl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LIBS)

check-orb: orb-bins
	@echo ""
	@echo ">>>> OrbStack / Docker multi-node (join, spawn, shard-prefix)"
	@chmod +x tests/orb/run_orb.sh
	@ORB_CTL=$(BINDIR)/orb_ctl ./tests/orb/run_orb.sh all

# Full suite for a normal terminal / CI (not agent sandbox)
check: check-sandbox unit check-integration
	@echo ""
	@echo "All DisLMDB suites PASSED (add 'make check-orb' when Docker/OrbStack is available)."

test: check-sandbox

# pkg-config fragment for C ABI consumers (bindings/ABI.kdl)
PREFIX ?= /usr/local
pc: | dirs
	@sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|0.1.0|g' dislmdb.pc.in \
	  > $(BUILD)/dislmdb.pc
	@echo "Wrote $(BUILD)/dislmdb.pc (PKG_CONFIG_PATH=$(abspath $(BUILD)))"

# High-level Rust binding (edition 2024); requires `make lib` first
rust-bindings: lib
	@cd bindings/rust && cargo test

# Thin Go cgo binding; requires `make lib` first (soft-skip if go missing)
go-bindings: lib
	@if command -v go >/dev/null 2>&1; then \
	  cd bindings/go && go test; \
	else \
	  echo "go-bindings: go toolchain not found — skipped (bindings/go sources still present)"; \
	fi

clean:
	rm -rf $(BUILD)
	-$(MAKE) -C $(MBEDTLS_LIBDIR) clean
