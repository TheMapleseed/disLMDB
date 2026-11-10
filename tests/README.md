# DisLMDB Test Suites

The default build (`make` / CMake `build_and_test`) compiles the library and **runs every suite below**.

## Layout

```
tests/
  harness/test_harness.h     Shared PASS/FAIL helpers
  unit/                      Pure / near-pure unit tests
  integration/               Env + DB + consensus APIs
  dislmdb_test.c             Legacy basic LMDB smoke suite
  e2e/
    e2e_runner.c             Scenario interpreter
    scenarios/*.in           Scripted inputs
    expected/*.out           Golden outputs
    run_e2e.sh               Diff runner vs goldens
```

## Commands

```bash
make check          # unit + integration + e2e
make unit
make integration
make e2e
```

## E2E golden workflow

1. Edit or add `tests/e2e/scenarios/<name>.in`.
2. Run `build/bin/e2e_runner tests/e2e/scenarios/<name>.in` from `build/` (or via `make e2e`).
3. Review output; place the approved transcript in `tests/e2e/expected/<name>.out`.
4. Subsequent builds fail if output drifts from the golden file.

Scenario language is documented at the top of `e2e_runner.c`.
