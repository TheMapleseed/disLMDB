# DisLMDB OrbStack / Docker multi-node image (Linux + OpenSSL).
# Build from repo root: docker build -f tests/orb/Dockerfile -t dislmdb-orb:local .
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang make ca-certificates libssl-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Bookworm clang-14 speaks C23 as -std=c2x; force Linux OpenSSL path.
# Mbed TLS static libs must be -fPIC for linking into libdislmdb.so.
RUN make clean \
 && make -C third_party/mbedtls/library CC=clang CFLAGS="-O2 -fPIC" \
      libmbedtls.a libmbedx509.a libmbedcrypto.a \
 && make lib build/bin/orb_node_agent build/bin/orb_ctl \
      CC=clang \
      STD=-std=c2x \
      CPPFLAGS="-D_DEFAULT_SOURCE -Iinclude -Isrc -IEnhanced-PBFT-mechanism -IEnhanced-Raft-mechanism -Ithird_party/mbedtls/include -DDISLMDB_USE_OPENSSL" \
      LIBS="-lpthread -luuid -lcrypto" \
      RPATH="-Wl,-rpath,/opt/dislmdb/lib" \
      SHARED_EXT=so \
      SHARED_FLAGS="-shared -Wl,-soname,libdislmdb.so"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 libuuid1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/lib/libdislmdb.so /opt/dislmdb/lib/
COPY --from=build /src/build/bin/orb_node_agent /opt/dislmdb/bin/orb_node_agent
COPY --from=build /src/build/bin/orb_ctl /opt/dislmdb/bin/orb_ctl

ENV PATH="/opt/dislmdb/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LD_LIBRARY_PATH="/opt/dislmdb/lib"

WORKDIR /data
EXPOSE 9876 19876
ENTRYPOINT ["/opt/dislmdb/bin/orb_node_agent"]
