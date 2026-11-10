# DisLMDB Makefile (no Homebrew / no CMake required on macOS)
# Uses Apple CommonCrypto + uuid from the system SDK.
# `make` / `make all` builds libraries, examples, and runs the full test suite.

CC       ?= clang
STD      ?= -std=c23
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic $(STD) -fPIC
CPPFLAGS += -Iinclude -Isrc -IEnhanced-PBFT-mechanism -DDISLMDB_USE_COMMONCRYPTO
LDFLAGS  ?=
LIBS     ?= -lpthread

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LIBS += -framework Security
  RPATH := -Wl,-rpath,@loader_path/../lib
else
  LIBS += -luuid -lcrypto
  CPPFLAGS := $(filter-out -DDISLMDB_USE_COMMONCRYPTO,$(CPPFLAGS)) -DDISLMDB_USE_OPENSSL
  RPATH := -Wl,-rpath,'$$ORIGIN/../lib'
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
  src/utils/dislmdb_persist.c \
  src/network/dislmdb_network.c \
  src/consensus/dislmdb_consensus.c \
  src/consensus/pbft_adapter.c \
  Enhanced-PBFT-mechanism/epdft.c \
  Enhanced-PBFT-mechanism/messaging.c \
  Enhanced-PBFT-mechanism/security_manager.c \
  Enhanced-PBFT-mechanism/blake3_ref.c \
  Enhanced-PBFT-mechanism/time_variant_blake3.c

LMDB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LMDB_SRCS))
DISLMDB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(DISLMDB_SRCS))

UNIT_TESTS := \
  $(BINDIR)/test_crypto \
  $(BINDIR)/test_tvb3

INTEGRATION_TESTS := \
  $(BINDIR)/test_ops_persist \
  $(BINDIR)/test_membership

BASIC_TEST := $(BINDIR)/dislmdb_test
E2E_RUNNER := $(BINDIR)/e2e_runner

.PHONY: all dirs lib examples test-bins check unit integration e2e test clean

# Default: build everything, then run the full suite (unit + integration + e2e)
all: lib examples test-bins check

dirs:
	@mkdir -p $(LIBDIR) $(BINDIR) \
	  $(OBJDIR)/src/utils $(OBJDIR)/src/network $(OBJDIR)/src/consensus \
	  $(OBJDIR)/Enhanced-PBFT-mechanism \
	  $(BUILD)/e2e_work

$(OBJDIR)/src/mdb.o $(OBJDIR)/src/midl.o: CPPFLAGS += -w

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIBDIR)/liblmdb.a: $(LMDB_OBJS) | dirs
	ar rcs $@ $^

$(LIBDIR)/libdislmdb.dylib: $(DISLMDB_OBJS) $(LIBDIR)/liblmdb.a | dirs
	$(CC) -shared -o $@ $(DISLMDB_OBJS) -L$(LIBDIR) -llmdb $(LIBS) $(LDFLAGS) \
	  -install_name @rpath/libdislmdb.dylib

lib: $(LIBDIR)/liblmdb.a $(LIBDIR)/libdislmdb.dylib

examples: $(BINDIR)/basic_example $(BINDIR)/distributed_example $(BINDIR)/bytecode_example

$(BINDIR)/basic_example: examples/basic_example.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/distributed_example: examples/distributed_example.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/bytecode_example: examples/bytecode_example.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

# --- Test binaries ----------------------------------------------------------

test-bins: $(BASIC_TEST) $(UNIT_TESTS) $(INTEGRATION_TESTS) $(E2E_RUNNER)

$(BASIC_TEST): tests/dislmdb_test.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_crypto: tests/unit/test_crypto.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_tvb3: tests/unit/test_tvb3.c Enhanced-PBFT-mechanism/time_variant_blake3.c \
		Enhanced-PBFT-mechanism/blake3_ref.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LIBS)

$(BINDIR)/test_ops_persist: tests/integration/test_ops_persist.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(BINDIR)/test_membership: tests/integration/test_membership.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

$(E2E_RUNNER): tests/e2e/e2e_runner.c $(LIBDIR)/libdislmdb.dylib | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -L$(LIBDIR) -ldislmdb $(LIBS) $(RPATH)

# --- Test execution (invoked by `all`) --------------------------------------

unit: $(UNIT_TESTS)
	@echo ""
	@echo ">>>> Unit tests"
	@$(BINDIR)/test_crypto
	@$(BINDIR)/test_tvb3

integration: $(INTEGRATION_TESTS) $(BASIC_TEST)
	@echo ""
	@echo ">>>> Integration / basic tests"
	@cd $(BINDIR) && ./dislmdb_test
	@cd $(BUILD) && ./bin/test_ops_persist
	@cd $(BUILD) && ./bin/test_membership

e2e: $(E2E_RUNNER)
	@echo ""
	@echo ">>>> End-to-end scenarios (golden I/O)"
	@chmod +x tests/e2e/run_e2e.sh
	@./tests/e2e/run_e2e.sh $(E2E_RUNNER)

check: unit integration e2e
	@echo ""
	@echo "All DisLMDB suites PASSED."

test: check

clean:
	rm -rf $(BUILD)
