# Third-party dependencies

## Mbed TLS (`mbedtls/`)

Portable TLS 1.3 stack used for DisLMDB mutual TLS. Same backend on every host —
no OS-localized TLS frameworks.

- Upstream: https://github.com/Mbed-TLS/mbedtls
- Version: 3.6.2 (Apache-2.0 OR GPL-2.0-or-later)
- Build: `make -C third_party/mbedtls/library` (invoked automatically by the
  top-level Makefile / CMake)

If this tree is missing, restore it with:

```bash
curl -fsSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.2.tar.gz \
  | tar xz -C third_party && mv third_party/mbedtls-3.6.2 third_party/mbedtls
```
