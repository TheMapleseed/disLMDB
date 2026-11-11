/**
 * @file dislmdb_admin.c
 * @brief Local admin CLI: offline env attach + live metrics file scrape.
 *
 * Usage:
 *   dislmdb_admin --path ./data metrics|checkpoint|sync|leader|status|export-metrics
 *   dislmdb_admin cat-metrics /run/dislmdb.prom
 *
 * Offline commands need exclusive LMDB lock (stop the node first).
 * Live scrape: set DISLMDB_METRICS_FILE on the node; sync/checkpoint refreshes it.
 */
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include "dislmdb_consensus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s --path <env_dir> [--solo|--raft|--pbft] <command>\n"
            "  %s cat-metrics <prometheus_file>\n"
            "Offline commands (exclusive LMDB lock):\n"
            "  metrics          Prometheus text via dislmdb_format_metrics\n"
            "  export-metrics   Write DISLMDB_METRICS_FILE or --out path\n"
            "  status           Confirm open succeeded\n"
            "  leader           Current leader id (Raft/PBFT)\n"
            "  checkpoint       dislmdb_checkpoint (+ metrics file refresh)\n"
            "  sync             dislmdb_force_sync (+ metrics file refresh)\n"
            "Live (no LMDB lock):\n"
            "  cat-metrics      Print a metrics file written by a running node\n",
            argv0, argv0);
}

static int open_env(const char *path, DISLMDB_CONSENSUS_MECHANISM mech,
                    DISLMDB_env **env_out)
{
    DISLMDB_env *env = NULL;
    int rc = dislmdb_env_create(&env);
    if (rc != 0) {
        return rc;
    }
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = path;
    cfg.mapsize = 64 * 1024 * 1024;
    cfg.maxdbs = 32;
    cfg.consensus.mechanism = mech;
    cfg.consensus.persist_state = true;
    cfg.network.local_port = 0;
    strncpy(cfg.node_name, "admin-cli", sizeof(cfg.node_name) - 1);
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *env_out = env;
    return 0;
}

static int cat_metrics_file(const char *file)
{
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "cannot open metrics file: %s\n", file);
        return 1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (fwrite(buf, 1, n, stdout) != n) {
            fclose(f);
            return 1;
        }
    }
    int err = ferror(f);
    fclose(f);
    return err ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *cmd = NULL;
    const char *out_path = NULL;
    const char *cat_file = NULL;
    DISLMDB_CONSENSUS_MECHANISM mech = DISLMDB_CONSENSUS_SOLO;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--solo") == 0) {
            mech = DISLMDB_CONSENSUS_SOLO;
        } else if (strcmp(argv[i], "--raft") == 0) {
            mech = DISLMDB_CONSENSUS_RAFT;
        } else if (strcmp(argv[i], "--pbft") == 0) {
            mech = DISLMDB_CONSENSUS_PBFT;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "cat-metrics") == 0 && i + 1 < argc) {
            cmd = "cat-metrics";
            cat_file = argv[++i];
        } else if (argv[i][0] != '-') {
            cmd = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (cmd && strcmp(cmd, "cat-metrics") == 0) {
        if (!cat_file) {
            usage(argv[0]);
            return 2;
        }
        return cat_metrics_file(cat_file);
    }

    if (!path || !cmd) {
        usage(argv[0]);
        return 2;
    }

    DISLMDB_env *env = NULL;
    int rc = open_env(path, mech, &env);
    if (rc != 0) {
        fprintf(stderr, "open failed: %s (%d)\n", dislmdb_strerror(rc), rc);
        return 1;
    }

    if (strcmp(cmd, "metrics") == 0) {
        DISLMDB_metrics m;
        memset(&m, 0, sizeof(m));
        rc = dislmdb_get_metrics(env, &m);
        if (rc == 0) {
            char buf[8192];
            size_t n = 0;
            rc = dislmdb_format_metrics(&m, buf, sizeof(buf), &n);
            if (rc == 0) {
                fwrite(buf, 1, n, stdout);
                if (n == 0 || buf[n - 1] != '\n') {
                    fputc('\n', stdout);
                }
            }
        }
    } else if (strcmp(cmd, "export-metrics") == 0) {
        rc = dislmdb_export_metrics_file(env, out_path);
        if (rc == 0) {
            printf("export-metrics=ok\n");
        }
    } else if (strcmp(cmd, "status") == 0) {
        printf("path=%s\n", path);
        printf("ok=1\n");
    } else if (strcmp(cmd, "leader") == 0) {
        char leader[128];
        memset(leader, 0, sizeof(leader));
        rc = dislmdb_get_leader(env, leader, sizeof(leader));
        if (rc == 0) {
            printf("leader=%s\n", leader[0] ? leader : "(none)");
        }
    } else if (strcmp(cmd, "checkpoint") == 0) {
        rc = dislmdb_checkpoint(env);
        if (rc == 0) {
            printf("checkpoint=ok\n");
        }
    } else if (strcmp(cmd, "sync") == 0) {
        rc = dislmdb_force_sync(env);
        if (rc == 0) {
            printf("sync=ok\n");
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        dislmdb_env_close(env);
        return 2;
    }

    if (rc != 0) {
        fprintf(stderr, "%s failed: %s (%d)\n", cmd, dislmdb_strerror(rc), rc);
        dislmdb_env_close(env);
        return 1;
    }
    dislmdb_env_close(env);
    return 0;
}
