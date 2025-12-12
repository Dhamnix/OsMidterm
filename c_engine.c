// Build: gcc -O2 -pthread -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 \
//              -o c_engine c_engine.c blake3.c blake3_dispatch.c blake3_portable.c
// Run:   ./c_engine /tmp/cengine.sock

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include "blake3.h"

// ==== Upload (both protocols agree on these per PDF/main.py) ====
#define OP_UPLOAD_START   0x01
#define OP_UPLOAD_CHUNK   0x02
#define OP_UPLOAD_FINISH  0x03
#define OP_UPLOAD_DONE    0x81

// ==== Download: main.py vs PDF differ ====
#define OP_DL_START_PDF   0x10
#define OP_DL_CHUNK_PDF   0x90
#define OP_DL_DONE_PDF    0x91

// main.py (gateway) uses different ones
#define OP_DL_START_GW    0x11
#define OP_DL_CHUNK_GW    0x91
#define OP_DL_DONE_GW     0x92

// ==== Error opcode per spec (used for PDF protocol) ====
#define OP_ERROR          0xFF

static const char* g_sock_path = NULL;

/* =======================
   Phase 4: Locks (kept)
   ======================= */
static pthread_rwlock_t g_manifest_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t  g_blocks_mutex    = PTHREAD_MUTEX_INITIALIZER;

/* =======================
   Phase 5: Thread Pool
   - real pool + queue with mutex/cond
   ======================= */
typedef enum {
    JOB_UPLOAD_CHUNK = 1,   // hash + write block
    JOB_DOWNLOAD_CHUNK = 2  // read + verify
} job_type_t;

typedef enum { PROTO_UNKNOWN = 0, PROTO_GW = 1, PROTO_PDF = 2 } proto_t;

/* Forward decl for contexts */
struct upload_ctx;
struct download_ctx;

typedef struct job {
    job_type_t type;
    struct job* next;

    union {
        struct {
            struct upload_ctx* ctx;
            unsigned idx;
            uint8_t* data;
            size_t   size;
        } up;

        struct {
            struct download_ctx* ctx;
            unsigned idx;
        } dl;
    } u;
} job_t;

typedef struct {
    pthread_t* threads;
    int        nthreads;

    job_t* head;
    job_t* tail;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int stop;
} thread_pool_t;

static thread_pool_t g_pool;

/* hash algorithm selector for multihash & manifest */
typedef enum {
    HASH_ALGO_BLAKE3 = 1
} hash_algo_t;

static const char* hash_algo_to_name(hash_algo_t algo) {
    switch (algo) {
        case HASH_ALGO_BLAKE3: return "blake3";
        default:               return "unknown";
    }
}

static uint8_t hash_algo_to_multihash_code(hash_algo_t algo) {
    switch (algo) {
        case HASH_ALGO_BLAKE3:
            /* Multihash code for BLAKE3-256 (placeholder if needed) */
            return 0x1f;
        default:
            return 0x00;
    }
}

static ssize_t read_n(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r == 0) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("read");
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int write_all(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            perror("write");
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

static int send_frame(int fd, uint8_t op, const void* payload, uint32_t len) {
    uint8_t header[5];
    header[0] = op;
    uint32_t be_len = htonl(len);
    memcpy(header + 1, &be_len, 4);
    if (write_all(fd, header, 5) < 0) return -1;
    if (len && write_all(fd, payload, len) < 0) return -1;
    return 0;
}

/* very small helper: extract filename from JSON-like payload:
   looks for "filename":"...." and returns 1 if found */
static int extract_filename_from_json(const char* json, size_t len, char out[256]) {
    (void)len;
    out[0] = '\0';
    const char* k = strstr(json, "\"filename\"");
    if (!k) return 0;

    const char* colon = strchr(k, ':');
    if (!colon) return 0;

    const char* q1 = strchr(colon, '"');
    if (!q1) return 0;
    const char* q2 = strchr(q1 + 1, '"');
    if (!q2) return 0;

    size_t n = (size_t)(q2 - (q1 + 1));
    if (n >= 255) n = 255;
    memcpy(out, q1 + 1, n);
    out[n] = '\0';
    return 1;
}

/* CID safety check (avoid path traversal) */
static int cid_is_safe(const char* cid) {
    if (!cid || !cid[0]) return 0;
    if (strstr(cid, "..") != NULL) return 0;
    for (const char* p = cid; *p; ++p) {
        if (*p == '/' || *p == '\\') return 0;
        if ((unsigned char)*p < 32) return 0;
    }
    return 1;
}

/* Error sender: PDF gets OP_ERROR with JSON payload; GW gets behavior that main.py tolerates. */
static void send_error(proto_t proto, int cfd,
                       uint8_t gw_done_op_for_download, /* pass OP_DL_DONE_GW when in download; else 0 */
                       const char* code,
                       const char* message) {
    if (proto == PROTO_PDF) {
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
                         "{\"code\":\"%s\",\"message\":\"%s\"}",
                         code ? code : "E_PROTO",
                         message ? message : "error");
        if (n < 0) n = 0;
        if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
        send_frame(cfd, OP_ERROR, buf, (uint32_t)n);
        return;
    }

    /* PROTO_GW: do not send OP_ERROR because main.py may not handle it.
       - upload: send UPLOAD_DONE with CID-ERROR:<CODE>
       - download: send DONE only */
    if (gw_done_op_for_download != 0) {
        send_frame(cfd, gw_done_op_for_download, NULL, 0);
    } else {
        char cid_buf[256];
        snprintf(cid_buf, sizeof(cid_buf), "CID-ERROR:%s", code ? code : "E_PROTO");
        send_frame(cfd, OP_UPLOAD_DONE, cid_buf, (uint32_t)strlen(cid_buf));
    }
}

/* ---- Atomic write helpers ---- */

static int fsync_dir_of_path(const char* path) {
    char tmp[800];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char* slash = strrchr(tmp, '/');
    if (!slash) return 0;
    *slash = '\0';

    int dfd = open(tmp, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int rc = fsync(dfd);
    close(dfd);
    return rc;
}

static int write_file_atomic(const char* final_path, const void* data, size_t len, mode_t mode) {
    char tmp_path[900];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d.%lu",
             final_path, (int)getpid(), (unsigned long)pthread_self());

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;

    const uint8_t* p = (const uint8_t*)data;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmp_path);
            return -1;
        }
        off += (size_t)w;
    }

    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    if (close(fd) != 0) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    if (fsync_dir_of_path(final_path) != 0) {
        return -1;
    }
    return 0;
}

/* ---- Crash recovery cleanup of leftover tmp files ---- */

static int has_tmp_marker(const char* name) {
    return (name && strstr(name, ".tmp.") != NULL);
}

static void cleanup_tmp_in_dir_shallow(const char* dirpath) {
    DIR* d = opendir(dirpath);
    if (!d) return;

    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (!has_tmp_marker(de->d_name)) continue;

        char full[1000];
        snprintf(full, sizeof(full), "%s/%s", dirpath, de->d_name);
        if (unlink(full) == 0) {
            fprintf(stderr, "[ENGINE] cleanup: removed leftover tmp %s\n", full);
        }
    }
    closedir(d);
}

static void cleanup_tmp_in_blocks(void) {
    DIR* d1 = opendir("blocks");
    if (!d1) return;

    struct dirent* e1;
    while ((e1 = readdir(d1)) != NULL) {
        if (strcmp(e1->d_name, ".") == 0 || strcmp(e1->d_name, "..") == 0) continue;

        char p1[256];
        snprintf(p1, sizeof(p1), "blocks/%s", e1->d_name);

        DIR* d2 = opendir(p1);
        if (!d2) continue;

        struct dirent* e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (strcmp(e2->d_name, ".") == 0 || strcmp(e2->d_name, "..") == 0) continue;

            char p2[512];
            snprintf(p2, sizeof(p2), "%s/%s", p1, e2->d_name);

            cleanup_tmp_in_dir_shallow(p2);
        }
        closedir(d2);
    }
    closedir(d1);
}

static void ensure_block_dirs(const char* chunk_hash_hex) {
    mkdir("blocks", 0777);
    char dir1[64], dir2[96];
    snprintf(dir1, sizeof(dir1), "blocks/%.2s", chunk_hash_hex);
    mkdir(dir1, 0777);
    snprintf(dir2, sizeof(dir2), "%s/%.2s", dir1, chunk_hash_hex + 2);
    mkdir(dir2, 0777);
}

/* =========================
   Thread Pool implementation
   ========================= */

static void pool_init(thread_pool_t* p, int nthreads);
static void pool_submit(thread_pool_t* p, job_t* j);

static void set_pool_error_string(char* dst, size_t cap, const char* s) {
    if (!dst || cap == 0) return;
    if (!s) { dst[0] = '\0'; return; }
    strncpy(dst, s, cap - 1);
    dst[cap - 1] = '\0';
}

/* =========================
   Upload chunk results / ctx
   ========================= */
typedef struct {
    int done;
    size_t size;
    char hash_hex[BLAKE3_OUT_LEN * 2 + 1];
} upload_chunk_result_t;

typedef struct upload_ctx {
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int pending;
    int inflight;
    int error;

    char err_code[32];
    char err_msg[160];

    upload_chunk_result_t* res;
    unsigned cap;
    unsigned count;
} upload_ctx_t;

static void upload_ctx_init(upload_ctx_t* c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->m, NULL);
    pthread_cond_init(&c->cv, NULL);
}

static void upload_ctx_destroy(upload_ctx_t* c) {
    if (c->res) free(c->res);
    pthread_mutex_destroy(&c->m);
    pthread_cond_destroy(&c->cv);
}

static int upload_ctx_ensure(upload_ctx_t* c, unsigned need) {
    if (need <= c->cap) return 0;
    unsigned newcap = c->cap ? c->cap : 16;
    while (newcap < need) newcap *= 2;
    upload_chunk_result_t* nr = (upload_chunk_result_t*)realloc(c->res, newcap * sizeof(upload_chunk_result_t));
    if (!nr) return -1;
    /* zero new area */
    for (unsigned i = c->cap; i < newcap; ++i) {
        nr[i].done = 0;
        nr[i].size = 0;
        nr[i].hash_hex[0] = '\0';
    }
    c->res = nr;
    c->cap = newcap;
    return 0;
}

/* ==========================
   Download chunk results / ctx
   ========================== */
typedef struct {
    int done;
    int ok;
    uint8_t* data;
    size_t   size;
} download_chunk_result_t;

typedef struct download_ctx {
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int error;

    char err_code[32];
    char err_msg[160];

    /* input arrays from manifest */
    unsigned n;
    char**   hashes;  // hex strings
    size_t*  sizes;

    /* results */
    download_chunk_result_t* res;

    int inflight;
    unsigned next_submit;
} download_ctx_t;

static void download_ctx_init(download_ctx_t* c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->m, NULL);
    pthread_cond_init(&c->cv, NULL);
}

static void download_ctx_destroy(download_ctx_t* c) {
    if (c->hashes) {
        for (unsigned i = 0; i < c->n; ++i) free(c->hashes[i]);
        free(c->hashes);
    }
    if (c->sizes) free(c->sizes);
    if (c->res) {
        for (unsigned i = 0; i < c->n; ++i) {
            free(c->res[i].data);
        }
        free(c->res);
    }
    pthread_mutex_destroy(&c->m);
    pthread_cond_destroy(&c->cv);
}

/* =========================
   Worker: do jobs
   ========================= */
static void* pool_worker(void* arg) {
    (void)arg;

    for (;;) {
        pthread_mutex_lock(&g_pool.m);
        while (!g_pool.stop && g_pool.head == NULL) {
            pthread_cond_wait(&g_pool.cv, &g_pool.m);
        }
        if (g_pool.stop) {
            pthread_mutex_unlock(&g_pool.m);
            break;
        }
        job_t* j = g_pool.head;
        g_pool.head = j->next;
        if (!g_pool.head) g_pool.tail = NULL;
        pthread_mutex_unlock(&g_pool.m);

        if (j->type == JOB_UPLOAD_CHUNK) {
            upload_ctx_t* ctx = j->u.up.ctx;
            unsigned idx = j->u.up.idx;
            uint8_t* data = j->u.up.data;
            size_t   size = j->u.up.size;

            /* compute hash */
            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, data, size);
            uint8_t digest[BLAKE3_OUT_LEN];
            blake3_hasher_finalize(&h, digest, BLAKE3_OUT_LEN);

            char hex[BLAKE3_OUT_LEN * 2 + 1];
            static const char hd[] = "0123456789abcdef";
            for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                hex[2*i]   = hd[digest[i] >> 4];
                hex[2*i+1] = hd[digest[i] & 0x0F];
            }
            hex[BLAKE3_OUT_LEN*2] = '\0';

            ensure_block_dirs(hex);

            char block_path[240];
            snprintf(block_path, sizeof(block_path),
                     "blocks/%.2s/%.2s/%s",
                     hex, hex + 2, hex);

            /* write block atomically with dedup protection */
            int fail = 0;
            pthread_mutex_lock(&g_blocks_mutex);
            FILE* bf = fopen(block_path, "rb");
            if (bf) {
                fclose(bf);
            } else {
                if (write_file_atomic(block_path, data, size, 0644) != 0) {
                    fail = 1;
                }
            }
            pthread_mutex_unlock(&g_blocks_mutex);

            pthread_mutex_lock(&ctx->m);
            if (!ctx->error) {
                if (fail) {
                    ctx->error = 1;
                    set_pool_error_string(ctx->err_code, sizeof(ctx->err_code), "E_BUSY");
                    set_pool_error_string(ctx->err_msg,  sizeof(ctx->err_msg),  "cannot write block");
                } else {
                    if (upload_ctx_ensure(ctx, idx + 1) != 0) {
                        ctx->error = 1;
                        set_pool_error_string(ctx->err_code, sizeof(ctx->err_code), "E_BUSY");
                        set_pool_error_string(ctx->err_msg,  sizeof(ctx->err_msg),  "out of memory");
                    } else {
                        ctx->res[idx].done = 1;
                        ctx->res[idx].size = size;
                        strncpy(ctx->res[idx].hash_hex, hex, sizeof(ctx->res[idx].hash_hex) - 1);
                        ctx->res[idx].hash_hex[sizeof(ctx->res[idx].hash_hex) - 1] = '\0';
                        if (idx + 1 > ctx->count) ctx->count = idx + 1;
                    }
                }
            }
            ctx->pending--;
            ctx->inflight--;
            pthread_cond_broadcast(&ctx->cv);
            pthread_mutex_unlock(&ctx->m);

            free(data);
            free(j);

        } else if (j->type == JOB_DOWNLOAD_CHUNK) {
            download_ctx_t* ctx = j->u.dl.ctx;
            unsigned idx = j->u.dl.idx;

            /* copy inputs safely */
            pthread_mutex_lock(&ctx->m);
            int already_err = ctx->error;
            pthread_mutex_unlock(&ctx->m);
            if (already_err) {
                /* don't waste work if already failed */
                pthread_mutex_lock(&ctx->m);
                ctx->inflight--;
                pthread_cond_broadcast(&ctx->cv);
                pthread_mutex_unlock(&ctx->m);
                free(j);
                continue;
            }

            const char* hex = ctx->hashes[idx];
            size_t size = ctx->sizes[idx];

            char block_path[240];
            snprintf(block_path, sizeof(block_path),
                     "blocks/%.2s/%.2s/%s",
                     hex, hex + 2, hex);

            uint8_t* buf = NULL;
            int ok = 0;
            const char* ecode = NULL;
            const char* emsg  = NULL;

            if (size == 0 || size > 1024ULL * 1024ULL) {
                ecode = "E_PROTO";
                emsg  = "bad chunk size";
                goto dl_done;
            }

            buf = (uint8_t*)malloc(size);
            if (!buf) {
                ecode = "E_BUSY";
                emsg  = "out of memory";
                goto dl_done;
            }

            pthread_mutex_lock(&g_blocks_mutex);
            FILE* bf = fopen(block_path, "rb");
            if (!bf) {
                pthread_mutex_unlock(&g_blocks_mutex);
                ecode = "E_NOT_FOUND";
                emsg  = "block not found";
                goto dl_done;
            }
            size_t rb = fread(buf, 1, size, bf);
            fclose(bf);
            pthread_mutex_unlock(&g_blocks_mutex);

            if (rb != size) {
                ecode = "E_PROTO";
                emsg  = "short read block";
                goto dl_done;
            }

            /* verify */
            blake3_hasher vh;
            blake3_hasher_init(&vh);
            blake3_hasher_update(&vh, buf, size);
            uint8_t digest[BLAKE3_OUT_LEN];
            blake3_hasher_finalize(&vh, digest, BLAKE3_OUT_LEN);

            char verify_hex[BLAKE3_OUT_LEN * 2 + 1];
            static const char hd2[] = "0123456789abcdef";
            for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                verify_hex[2*i]   = hd2[digest[i] >> 4];
                verify_hex[2*i+1] = hd2[digest[i] & 0x0F];
            }
            verify_hex[BLAKE3_OUT_LEN*2] = '\0';

            if (strcmp(verify_hex, hex) != 0) {
                ecode = "E_HASH_MISMATCH";
                emsg  = "verify failed";
                goto dl_done;
            }

            ok = 1;

        dl_done:
            pthread_mutex_lock(&ctx->m);
            if (!ctx->error) {
                if (!ok) {
                    ctx->error = 1;
                    set_pool_error_string(ctx->err_code, sizeof(ctx->err_code), ecode ? ecode : "E_PROTO");
                    set_pool_error_string(ctx->err_msg,  sizeof(ctx->err_msg),  emsg  ? emsg  : "download failed");
                    free(buf);
                } else {
                    ctx->res[idx].done = 1;
                    ctx->res[idx].ok   = 1;
                    ctx->res[idx].data = buf;
                    ctx->res[idx].size = size;
                }
            } else {
                free(buf);
            }
            ctx->inflight--;
            pthread_cond_broadcast(&ctx->cv);
            pthread_mutex_unlock(&ctx->m);

            free(j);
        } else {
            free(j);
        }
    }

    return NULL;
}

static void pool_init(thread_pool_t* p, int nthreads) {
    memset(p, 0, sizeof(*p));
    pthread_mutex_init(&p->m, NULL);
    pthread_cond_init(&p->cv, NULL);
    p->stop = 0;

    p->nthreads = nthreads;
    p->threads = (pthread_t*)calloc((size_t)nthreads, sizeof(pthread_t));
    if (!p->threads) {
        perror("calloc pool threads");
        exit(2);
    }

    for (int i = 0; i < nthreads; ++i) {
        if (pthread_create(&p->threads[i], NULL, pool_worker, NULL) != 0) {
            perror("pthread_create worker");
            exit(2);
        }
    }
}

static void pool_submit(thread_pool_t* p, job_t* j) {
    j->next = NULL;
    pthread_mutex_lock(&p->m);
    if (!p->tail) {
        p->head = p->tail = j;
    } else {
        p->tail->next = j;
        p->tail = j;
    }
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->m);
}

/* =========================
   Manifest parsing to arrays
   ========================= */
static int parse_manifest_chunks(const char* manifest, char*** out_hashes, size_t** out_sizes, unsigned* out_n) {
    *out_hashes = NULL;
    *out_sizes = NULL;
    *out_n = 0;

    const char* p = strstr(manifest, "\"chunks\"");
    if (!p) return -1;
    p = strchr(p, '[');
    if (!p) return -1;
    p++;

    unsigned cap = 16;
    unsigned n = 0;
    char** hashes = (char**)calloc(cap, sizeof(char*));
    size_t* sizes = (size_t*)calloc(cap, sizeof(size_t));
    if (!hashes || !sizes) {
        free(hashes); free(sizes);
        return -1;
    }

    while (1) {
        const char* idx_key = strstr(p, "\"index\"");
        if (!idx_key) break;

        const char* size_key = strstr(idx_key, "\"size\"");
        const char* hash_key = strstr(idx_key, "\"hash\"");
        if (!size_key || !hash_key) break;

        const char* size_colon = strchr(size_key, ':');
        if (!size_colon) break;
        unsigned long long sz = strtoull(size_colon + 1, NULL, 10);
        if (sz == 0) break;

        const char* q1 = strchr(hash_key, '"');
        if (!q1) break;
        const char* q2 = strchr(q1 + 1, '"');
        if (!q2) break;
        const char* q3 = strchr(q2 + 1, '"');
        if (!q3) break;
        const char* q4 = strchr(q3 + 1, '"');
        if (!q4) break;

        size_t hlen = (size_t)(q4 - (q3 + 1));
        if (hlen < 4 || hlen >= BLAKE3_OUT_LEN * 2 + 1) break;

        if (n == cap) {
            cap *= 2;
            char** nh = (char**)realloc(hashes, cap * sizeof(char*));
            size_t* ns = (size_t*)realloc(sizes, cap * sizeof(size_t));
            if (!nh || !ns) {
                free(nh); free(ns);
                for (unsigned i = 0; i < n; ++i) free(hashes[i]);
                free(hashes); free(sizes);
                return -1;
            }
            hashes = nh; sizes = ns;
        }

        hashes[n] = (char*)malloc(hlen + 1);
        if (!hashes[n]) {
            for (unsigned i = 0; i < n; ++i) free(hashes[i]);
            free(hashes); free(sizes);
            return -1;
        }
        memcpy(hashes[n], q3 + 1, hlen);
        hashes[n][hlen] = '\0';
        sizes[n] = (size_t)sz;

        n++;
        p = q4 + 1;
    }

    *out_hashes = hashes;
    *out_sizes = sizes;
    *out_n = n;
    return (n > 0) ? 0 : -1;
}

/* =======================
   Connection handler
   - still thread-per-connection
   - chunk work goes to pool (Phase 5)
   ======================= */

static void* handle_connection(void* arg) {
    int cfd = (int)(intptr_t)arg;

    const hash_algo_t HASH_ALGO = HASH_ALGO_BLAKE3;

    char upload_filename[256];
    upload_filename[0] = '\0';

    proto_t proto = PROTO_UNKNOWN;

    for (;;) {
        uint8_t header[5];
        ssize_t r = read_n(cfd, header, 5);
        if (r == 0) break;
        if (r < 0) break;

        uint8_t op = header[0];
        uint32_t len;
        memcpy(&len, header + 1, 4);
        len = ntohl(len);

        uint8_t* payload = NULL;
        if (len) {
            payload = (uint8_t*)malloc(len + 1);
            if (!payload) { perror("malloc"); break; }
            if (read_n(cfd, payload, len) <= 0) { free(payload); break; }
            payload[len] = '\0';
        }

        if (op == OP_UPLOAD_START) {
            printf("[ENGINE] UPLOAD_START: payload=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);

            if (proto == PROTO_UNKNOWN) {
                if (len > 0 && ((char*)payload)[0] == '{') proto = PROTO_PDF;
                else proto = PROTO_GW;
            }

            if (proto == PROTO_GW) {
                size_t name_len = len < sizeof(upload_filename) - 1 ? len : sizeof(upload_filename) - 1;
                memcpy(upload_filename, payload, name_len);
                upload_filename[name_len] = '\0';
            } else {
                if (!extract_filename_from_json((char*)payload, len, upload_filename)) {
                    strncpy(upload_filename, "uploaded.bin", sizeof(upload_filename) - 1);
                    upload_filename[sizeof(upload_filename) - 1] = '\0';
                }
            }

            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "wb");
            if (!f) {
                perror("fopen upload start");
                send_error(proto, cfd, 0, "E_BUSY", "cannot create temp upload file");
            } else {
                fclose(f);
            }

        } else if (op == OP_UPLOAD_CHUNK) {
            if (proto == PROTO_UNKNOWN) {
                send_error(PROTO_GW, cfd, 0, "E_PROTO", "UPLOAD_CHUNK before UPLOAD_START");
                free(payload);
                continue;
            }

            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "ab");
            if (!f) {
                perror("fopen upload chunk");
                send_error(proto, cfd, 0, "E_BUSY", "cannot append to temp upload file");
            } else {
                const uint8_t* data = payload;
                uint32_t data_len = len;

                if (proto == PROTO_PDF && len > 4) {
                    data = payload + 4;
                    data_len = len - 4;
                }

                if (data_len > 0) {
                    size_t written = fwrite(data, 1, data_len, f);
                    if (written != data_len) {
                        perror("fwrite upload chunk");
                        send_error(proto, cfd, 0, "E_BUSY", "write failed");
                    }
                }
                fclose(f);
            }

        } else if (op == OP_UPLOAD_FINISH) {
            const unsigned int chunk_size = 262144;
            const int MAX_INFLIGHT = 8; /* window to limit memory */

            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);

            FILE* f = fopen(path, "rb");
            if (!f) {
                perror("fopen for manifest");
                send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "cannot open temp upload file");
            } else {
                mkdir("blocks", 0777);
                mkdir("manifests", 0777);

                upload_ctx_t uctx;
                upload_ctx_init(&uctx);

                unsigned long long total_size = 0ULL;
                unsigned idx = 0;

                uint8_t* buf = (uint8_t*)malloc(chunk_size);
                if (!buf) {
                    fclose(f);
                    upload_ctx_destroy(&uctx);
                    send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "out of memory");
                    goto up_done;
                }

                /* submit jobs while reading */
                for (;;) {
                    size_t nread = fread(buf, 1, chunk_size, f);
                    if (nread == 0) break;
                    total_size += nread;

                    uint8_t* copy = (uint8_t*)malloc(nread);
                    if (!copy) {
                        pthread_mutex_lock(&uctx.m);
                        uctx.error = 1;
                        set_pool_error_string(uctx.err_code, sizeof(uctx.err_code), "E_BUSY");
                        set_pool_error_string(uctx.err_msg, sizeof(uctx.err_msg), "out of memory");
                        pthread_cond_broadcast(&uctx.cv);
                        pthread_mutex_unlock(&uctx.m);
                        break;
                    }
                    memcpy(copy, buf, nread);

                    job_t* j = (job_t*)calloc(1, sizeof(job_t));
                    if (!j) {
                        free(copy);
                        pthread_mutex_lock(&uctx.m);
                        uctx.error = 1;
                        set_pool_error_string(uctx.err_code, sizeof(uctx.err_code), "E_BUSY");
                        set_pool_error_string(uctx.err_msg, sizeof(uctx.err_msg), "out of memory");
                        pthread_cond_broadcast(&uctx.cv);
                        pthread_mutex_unlock(&uctx.m);
                        break;
                    }

                    pthread_mutex_lock(&uctx.m);
                    while (!uctx.error && uctx.inflight >= MAX_INFLIGHT) {
                        pthread_cond_wait(&uctx.cv, &uctx.m);
                    }
                    if (uctx.error) {
                        pthread_mutex_unlock(&uctx.m);
                        free(copy);
                        free(j);
                        break;
                    }
                    uctx.pending++;
                    uctx.inflight++;
                    pthread_mutex_unlock(&uctx.m);

                    j->type = JOB_UPLOAD_CHUNK;
                    j->u.up.ctx  = &uctx;
                    j->u.up.idx  = idx;
                    j->u.up.data = copy;
                    j->u.up.size = nread;

                    pool_submit(&g_pool, j);
                    idx++;
                }

                free(buf);
                fclose(f);

                /* wait all jobs done */
                pthread_mutex_lock(&uctx.m);
                while (uctx.pending > 0) {
                    pthread_cond_wait(&uctx.cv, &uctx.m);
                }
                int err = uctx.error;
                char ecode[32]; char emsg[160];
                set_pool_error_string(ecode, sizeof(ecode), uctx.err_code);
                set_pool_error_string(emsg,  sizeof(emsg),  uctx.err_msg);
                pthread_mutex_unlock(&uctx.m);

                if (err) {
                    upload_ctx_destroy(&uctx);
                    send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, ecode[0]?ecode:"E_BUSY", emsg[0]?emsg:"upload failed");
                    goto up_done;
                }

                /* build chunks_json in order */
                char chunks_json[8192];
                size_t chunks_len = 0;
                chunks_json[0] = '\0';

                for (unsigned i = 0; i < uctx.count; ++i) {
                    if (!uctx.res[i].done) {
                        upload_ctx_destroy(&uctx);
                        send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "missing chunk result");
                        goto up_done;
                    }

                    char entry[256];
                    int entry_len = snprintf(entry, sizeof(entry),
                        "%s{\"index\":%u,\"size\":%zu,\"hash\":\"%s\"}",
                        (i == 0 ? "" : ","), i, uctx.res[i].size, uctx.res[i].hash_hex);

                    if (entry_len <= 0 || chunks_len + (size_t)entry_len >= sizeof(chunks_json)) {
                        upload_ctx_destroy(&uctx);
                        send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "manifest too large");
                        goto up_done;
                    }

                    memcpy(chunks_json + chunks_len, entry, (size_t)entry_len);
                    chunks_len += (size_t)entry_len;
                    chunks_json[chunks_len] = '\0';
                }

                upload_ctx_destroy(&uctx);

                const char* hash_algo_name = hash_algo_to_name(HASH_ALGO);
                const char* filename = (upload_filename[0] != '\0') ? upload_filename : path;

                char manifest[16384];
                int manifest_len = snprintf(
                    manifest, sizeof(manifest),
                    "{\"version\":1,"
                    "\"hash_algo\":\"%s\","
                    "\"chunk_size\":%u,"
                    "\"total_size\":%llu,"
                    "\"filename\":\"%s\","
                    "\"chunks\":[%s]}",
                    hash_algo_name, chunk_size, total_size, filename, chunks_json
                );

                if (manifest_len <= 0 || manifest_len >= (int)sizeof(manifest)) {
                    send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "manifest build failed");
                    goto up_done;
                }

                /* CID = base32(multicodec(manifest) + multihash(manifest)) */
                blake3_hasher man_hasher;
                blake3_hasher_init(&man_hasher);
                blake3_hasher_update(&man_hasher, manifest, (size_t)manifest_len);

                uint8_t man_hash[BLAKE3_OUT_LEN];
                blake3_hasher_finalize(&man_hasher, man_hash, BLAKE3_OUT_LEN);

                uint8_t hash_code = hash_algo_to_multihash_code(HASH_ALGO);
                uint8_t multihash[2 + BLAKE3_OUT_LEN];
                size_t multihash_len = 0;
                multihash[multihash_len++] = hash_code;
                multihash[multihash_len++] = (uint8_t)BLAKE3_OUT_LEN;
                memcpy(multihash + multihash_len, man_hash, BLAKE3_OUT_LEN);
                multihash_len += BLAKE3_OUT_LEN;

                const uint8_t CODEC_MANIFEST = 0x71; /* placeholder */
                uint8_t cid_bytes[1 + sizeof(multihash)];
                size_t cid_bytes_len = 0;
                cid_bytes[cid_bytes_len++] = CODEC_MANIFEST;
                memcpy(cid_bytes + cid_bytes_len, multihash, multihash_len);
                cid_bytes_len += multihash_len;

                static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
                char cid_str[1 + ((1 + sizeof(multihash) + 4) / 5) * 8 + 1];
                size_t out_idx = 0;
                unsigned int bits = 0;
                unsigned int acc = 0;

                for (size_t i = 0; i < cid_bytes_len; ++i) {
                    acc = (acc << 8) | cid_bytes[i];
                    bits += 8;
                    while (bits >= 5) {
                        bits -= 5;
                        unsigned int aidx = (acc >> bits) & 0x1F;
                        cid_str[1 + out_idx++] = alphabet[aidx];
                    }
                }
                if (bits > 0) {
                    unsigned int aidx = (acc << (5 - bits)) & 0x1F;
                    cid_str[1 + out_idx++] = alphabet[aidx];
                }
                cid_str[0] = 'b';
                cid_str[1 + out_idx] = '\0';

                char manifest_path[380];
                snprintf(manifest_path, sizeof(manifest_path), "manifests/%s.json", cid_str);

                /* RW-lock writer for manifest */
                pthread_rwlock_wrlock(&g_manifest_rwlock);
                int wrc = write_file_atomic(manifest_path, manifest, (size_t)manifest_len, 0644);
                pthread_rwlock_unlock(&g_manifest_rwlock);

                if (wrc != 0) {
                    perror("atomic write manifest");
                    send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "cannot write manifest atomically");
                    goto up_done;
                }

                if (remove(path) != 0) perror("remove temp upload file");

                printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid_str);
                fflush(stdout);
                send_frame(cfd, OP_UPLOAD_DONE, cid_str, (uint32_t)strlen(cid_str));
            }

        up_done:
            ;

        } else if (op == OP_DL_START_GW || op == OP_DL_START_PDF) {
            if (proto == PROTO_UNKNOWN) {
                proto = (op == OP_DL_START_PDF) ? PROTO_PDF : PROTO_GW;
            }

            uint8_t chunk_op = (proto == PROTO_PDF) ? OP_DL_CHUNK_PDF : OP_DL_CHUNK_GW;
            uint8_t done_op  = (proto == PROTO_PDF) ? OP_DL_DONE_PDF  : OP_DL_DONE_GW;

            printf("[ENGINE] DOWNLOAD_START: cid=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);

            char cid[256];
            size_t cid_len = len < sizeof(cid) - 1 ? len : sizeof(cid) - 1;
            memcpy(cid, payload, cid_len);
            cid[cid_len] = '\0';

            if (!cid_is_safe(cid)) {
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_BAD_CID", "unsafe cid");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }

            char manifest_path[512];
            snprintf(manifest_path, sizeof(manifest_path), "manifests/%s.json", cid);

            /* read manifest under RW-lock reader */
            pthread_rwlock_rdlock(&g_manifest_rwlock);
            FILE* mf = fopen(manifest_path, "rb");
            if (!mf) {
                pthread_rwlock_unlock(&g_manifest_rwlock);
                perror("fopen manifest");
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_NOT_FOUND", "manifest not found");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }

            if (fseek(mf, 0, SEEK_END) != 0) {
                fclose(mf);
                pthread_rwlock_unlock(&g_manifest_rwlock);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest read failed");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }
            long msize_l = ftell(mf);
            if (msize_l < 0) {
                fclose(mf);
                pthread_rwlock_unlock(&g_manifest_rwlock);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest size error");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }
            size_t msize = (size_t)msize_l;
            rewind(mf);

            char* manifest = (char*)malloc(msize + 1);
            if (!manifest) {
                fclose(mf);
                pthread_rwlock_unlock(&g_manifest_rwlock);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_BUSY", "out of memory");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }

            size_t mr = fread(manifest, 1, msize, mf);
            fclose(mf);
            pthread_rwlock_unlock(&g_manifest_rwlock);
            if (mr != msize) {
                free(manifest);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest read short");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }
            manifest[msize] = '\0';

            download_ctx_t dctx;
            download_ctx_init(&dctx);

            /* parse chunks to arrays */
            char** hashes = NULL;
            size_t* sizes = NULL;
            unsigned n = 0;
            if (parse_manifest_chunks(manifest, &hashes, &sizes, &n) != 0) {
                free(manifest);
                download_ctx_destroy(&dctx);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "bad manifest chunks");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }
            free(manifest);

            dctx.n = n;
            dctx.hashes = hashes;
            dctx.sizes = sizes;
            dctx.res = (download_chunk_result_t*)calloc(n, sizeof(download_chunk_result_t));
            if (!dctx.res) {
                download_ctx_destroy(&dctx);
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_BUSY", "out of memory");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                free(payload);
                continue;
            }

            const int MAX_INFLIGHT = 8;
            dctx.inflight = 0;
            dctx.next_submit = 0;

            /* submit initial window */
            pthread_mutex_lock(&dctx.m);
            unsigned init = (n < (unsigned)MAX_INFLIGHT) ? n : (unsigned)MAX_INFLIGHT;
            for (unsigned i = 0; i < init; ++i) {
                job_t* j = (job_t*)calloc(1, sizeof(job_t));
                if (!j) {
                    dctx.error = 1;
                    set_pool_error_string(dctx.err_code, sizeof(dctx.err_code), "E_BUSY");
                    set_pool_error_string(dctx.err_msg,  sizeof(dctx.err_msg),  "out of memory");
                    break;
                }
                j->type = JOB_DOWNLOAD_CHUNK;
                j->u.dl.ctx = &dctx;
                j->u.dl.idx = i;
                dctx.inflight++;
                dctx.next_submit++;
                pool_submit(&g_pool, j);
            }
            pthread_mutex_unlock(&dctx.m);

            /* send in order */
            int failed = 0;
            char ecode[32] = {0}, emsg[160] = {0};

            for (unsigned i = 0; i < n; ++i) {
                pthread_mutex_lock(&dctx.m);
                while (!dctx.error && !dctx.res[i].done) {
                    pthread_cond_wait(&dctx.cv, &dctx.m);
                }
                if (dctx.error) {
                    failed = 1;
                    set_pool_error_string(ecode, sizeof(ecode), dctx.err_code);
                    set_pool_error_string(emsg,  sizeof(emsg),  dctx.err_msg);
                    pthread_mutex_unlock(&dctx.m);
                    break;
                }

                uint8_t* data = dctx.res[i].data;
                size_t   sz   = dctx.res[i].size;
                dctx.res[i].data = NULL; /* ownership moves */
                pthread_mutex_unlock(&dctx.m);

                /* send chunk */
                if (send_frame(cfd, chunk_op, data, (uint32_t)sz) < 0) {
                    free(data);
                    failed = 1;
                    strncpy(ecode, "E_BUSY", sizeof(ecode)-1);
                    strncpy(emsg,  "send failed", sizeof(emsg)-1);
                    break;
                }
                free(data);

                /* submit next chunk if any */
                pthread_mutex_lock(&dctx.m);
                if (!dctx.error && dctx.next_submit < n) {
                    job_t* j = (job_t*)calloc(1, sizeof(job_t));
                    if (!j) {
                        dctx.error = 1;
                        set_pool_error_string(dctx.err_code, sizeof(dctx.err_code), "E_BUSY");
                        set_pool_error_string(dctx.err_msg,  sizeof(dctx.err_msg),  "out of memory");
                        pthread_cond_broadcast(&dctx.cv);
                    } else {
                        unsigned k = dctx.next_submit++;
                        j->type = JOB_DOWNLOAD_CHUNK;
                        j->u.dl.ctx = &dctx;
                        j->u.dl.idx = k;
                        dctx.inflight++;
                        pool_submit(&g_pool, j);
                    }
                }
                pthread_mutex_unlock(&dctx.m);
            }

            if (failed) {
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), ecode[0]?ecode:"E_BUSY", emsg[0]?emsg:"download failed");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
            } else {
                send_frame(cfd, done_op, NULL, 0);
            }

            download_ctx_destroy(&dctx);

        } else {
            send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "unknown opcode");
        }

        free(payload);
    }

    close(cfd);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /tmp/cengine.sock\n", argv[0]);
        return 2;
    }
    g_sock_path = argv[1];

    /* cleanup leftovers from previous crash */
    mkdir("manifests", 0777);
    mkdir("blocks", 0777);
    cleanup_tmp_in_dir_shallow("manifests");
    cleanup_tmp_in_blocks();

    /* ===== Phase 5: start thread pool ===== */
    int nthreads = 4; /* safe default */
    pool_init(&g_pool, nthreads);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 2; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);

    unlink(g_sock_path);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 2; }
    if (listen(fd, 64) < 0) { perror("listen"); return 2; }

    printf("[ENGINE] listening on %s\n", g_sock_path);
    fflush(stdout);

    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        pthread_t th;
        if (pthread_create(&th, NULL, handle_connection, (void*)(intptr_t)cfd) != 0) {
            perror("pthread_create");
            close(cfd);
            continue;
        }
        pthread_detach(th);
    }

    close(fd);
    unlink(g_sock_path);
    return 0;
}
