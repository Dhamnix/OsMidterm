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

// ==== Error opcode per spec ====
#define OP_ERROR          0xFF

static const char* g_sock_path = NULL;

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

static int fsync_dir_of_path(const char* path) {
    // fsync the parent directory to persist rename() metadata
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char* slash = strrchr(tmp, '/');
    if (!slash) return 0; // no dir component
    *slash = '\0';

    int dfd = open(tmp, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int rc = fsync(dfd);
    close(dfd);
    return rc;
}

static int write_file_atomic(const char* final_path, const void* data, size_t len, mode_t mode) {
    // write to temp in same directory, fsync, then rename
    char tmp_path[600];
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

    // Make rename durable
    if (fsync_dir_of_path(final_path) != 0) {
        // Not fatal in many FS configs, but we report failure
        return -1;
    }
    return 0;
}


typedef enum { PROTO_UNKNOWN = 0, PROTO_GW = 1, PROTO_PDF = 2 } proto_t;

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

/* Basic CID safety check to prevent path traversal and obvious junk.
   Accepts:
   - base32-ish content ids starting with 'b' (pdf-style)
   - gateway may send anything, but we still block '/', '\\', and ".." */
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

            /* detect proto + parse filename accordingly */
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
            /* Protocol sanity: chunk before start */
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

            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);

            FILE* f = fopen(path, "rb");
            if (!f) {
                perror("fopen for manifest");
                send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "cannot open temp upload file");
            } else {
                mkdir("blocks", 0777);
                mkdir("manifests", 0777);

                uint8_t* buf = (uint8_t*)malloc(chunk_size);
                if (!buf) {
                    perror("malloc chunk buffer");
                    fclose(f);
                    send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "out of memory");
                } else {
                    unsigned long long total_size = 0ULL;
                    unsigned int chunk_index = 0;

                    char chunks_json[8192];
                    size_t chunks_len = 0;
                    chunks_json[0] = '\0';

                    size_t nread;
                    while ((nread = fread(buf, 1, chunk_size, f)) > 0) {
                        total_size += nread;

                        if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                            fprintf(stderr, "Unsupported HASH_ALGO for chunks\n");
                            send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "unsupported hash algo");
                            goto finish_cleanup;
                        }

                        blake3_hasher chunk_hasher;
                        blake3_hasher_init(&chunk_hasher);
                        blake3_hasher_update(&chunk_hasher, buf, nread);

                        uint8_t chunk_digest[BLAKE3_OUT_LEN];
                        blake3_hasher_finalize(&chunk_hasher, chunk_digest, BLAKE3_OUT_LEN);

                        char chunk_hash_hex[BLAKE3_OUT_LEN * 2 + 1];
                        static const char hex_digits[] = "0123456789abcdef";
                        for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                            chunk_hash_hex[2 * i]     = hex_digits[chunk_digest[i] >> 4];
                            chunk_hash_hex[2 * i + 1] = hex_digits[chunk_digest[i] & 0x0F];
                        }
                        chunk_hash_hex[BLAKE3_OUT_LEN * 2] = '\0';

                        char dir1[64], dir2[80], block_path[160];
                        snprintf(dir1, sizeof(dir1), "blocks/%.2s", chunk_hash_hex);
                        mkdir(dir1, 0777);

                        snprintf(dir2, sizeof(dir2), "%s/%.2s", dir1, chunk_hash_hex + 2);
                        mkdir(dir2, 0777);

                        snprintf(block_path, sizeof(block_path), "%s/%s", dir2, chunk_hash_hex);

                        FILE* bf = fopen(block_path, "rb");
                        if (bf) {
                            fclose(bf);
                        } else {
                            if (write_file_atomic(block_path, buf, nread, 0644) != 0) {
                            perror("atomic write block");
                            send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "cannot write block atomically");
                            }
                        }

                        char entry[256];
                        int entry_len = snprintf(
                            entry,
                            sizeof(entry),
                            "%s{\"index\":%u,\"size\":%zu,\"hash\":\"%s\"}",
                            (chunk_index == 0 ? "" : ","),
                            chunk_index,
                            nread,
                            chunk_hash_hex
                        );

                        if (entry_len <= 0 || chunks_len + (size_t)entry_len >= sizeof(chunks_json)) {
                            send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "manifest too large");
                            goto finish_cleanup;
                        }

                        memcpy(chunks_json + chunks_len, entry, (size_t)entry_len);
                        chunks_len += (size_t)entry_len;
                        chunks_json[chunks_len] = '\0';

                        ++chunk_index;
                    }

                    fclose(f);
                    f = NULL;

                    const char* hash_algo_name = hash_algo_to_name(HASH_ALGO);
                    const char* filename = (upload_filename[0] != '\0') ? upload_filename : path;

                    char manifest[16384];
                    int manifest_len = snprintf(
                        manifest,
                        sizeof(manifest),
                        "{\"version\":1,"
                        "\"hash_algo\":\"%s\","
                        "\"chunk_size\":%u,"
                        "\"total_size\":%llu,"
                        "\"filename\":\"%s\","
                        "\"chunks\":[%s]}",
                        hash_algo_name,
                        chunk_size,
                        total_size,
                        filename,
                        chunks_json
                    );

                    if (manifest_len <= 0 || manifest_len >= (int)sizeof(manifest)) {
                        send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "manifest build failed");
                        goto finish_cleanup;
                    }

                    if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                        send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_PROTO", "unsupported hash algo");
                        goto finish_cleanup;
                    }

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
                            unsigned int idx = (acc >> bits) & 0x1F;
                            cid_str[1 + out_idx++] = alphabet[idx];
                        }
                    }
                    if (bits > 0) {
                        unsigned int idx = (acc << (5 - bits)) & 0x1F;
                        cid_str[1 + out_idx++] = alphabet[idx];
                    }
                    cid_str[0] = 'b';
                    cid_str[1 + out_idx] = '\0';

                    char manifest_path[256];
                    snprintf(manifest_path, sizeof(manifest_path), "manifests/%s.json", cid_str);
                    // Atomic write manifest: write temp + fsync + rename
                    if (write_file_atomic(manifest_path, manifest, (size_t)manifest_len, 0644) != 0) {
                        perror("atomic write manifest");
                        send_error(proto == PROTO_UNKNOWN ? PROTO_GW : proto, cfd, 0, "E_BUSY", "cannot write manifest atomically");
                        goto finish_cleanup;
                    }


                    if (remove(path) != 0) perror("remove temp upload file");

                    printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid_str);
                    fflush(stdout);
                    send_frame(cfd, OP_UPLOAD_DONE, cid_str, (uint32_t)strlen(cid_str));

                finish_cleanup:
                    if (f) fclose(f);
                    free(buf);
                }
            }

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

            FILE* mf = fopen(manifest_path, "rb");
            if (!mf) {
                perror("fopen manifest");
                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_NOT_FOUND", "manifest not found");
                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
            } else {
                if (fseek(mf, 0, SEEK_END) != 0) {
                    perror("fseek manifest");
                    fclose(mf);
                    send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest read failed");
                    if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                } else {
                    long msize_l = ftell(mf);
                    if (msize_l < 0) {
                        perror("ftell manifest");
                        fclose(mf);
                        send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest size error");
                        if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                    } else {
                        size_t msize = (size_t)msize_l;
                        rewind(mf);

                        char* manifest = (char*)malloc(msize + 1);
                        if (!manifest) {
                            perror("malloc manifest");
                            fclose(mf);
                            send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_BUSY", "out of memory");
                            if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                        } else {
                            size_t mr = fread(manifest, 1, msize, mf);
                            fclose(mf);
                            if (mr != msize) {
                                perror("fread manifest");
                                free(manifest);
                                send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest read short");
                                if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                            } else {
                                manifest[msize] = '\0';

                                const char* p = strstr(manifest, "\"chunks\"");
                                if (!p) {
                                    fprintf(stderr, "manifest has no \"chunks\" field\n");
                                    send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "manifest missing chunks");
                                    if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                                    free(manifest);
                                } else {
                                    p = strchr(p, '[');
                                    if (!p) {
                                        fprintf(stderr, "manifest has no '[' for chunks array\n");
                                        send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), "E_PROTO", "bad chunks format");
                                        if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                                        free(manifest);
                                    } else {
                                        p++;

                                        int hard_fail = 0;
                                        const char* fail_code = NULL;
                                        const char* fail_msg  = NULL;

                                        while (1) {
                                            const char* idx_key = strstr(p, "\"index\"");
                                            if (!idx_key) break;

                                            const char* size_key = strstr(idx_key, "\"size\"");
                                            const char* hash_key = strstr(idx_key, "\"hash\"");
                                            if (!size_key || !hash_key) {
                                                hard_fail = 1; fail_code = "E_PROTO"; fail_msg = "chunk entry missing size/hash";
                                                break;
                                            }

                                            const char* idx_colon = strchr(idx_key, ':');
                                            if (!idx_colon) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad index"; break; }
                                            unsigned long index = strtoul(idx_colon + 1, NULL, 10);
                                            (void)index;

                                            const char* size_colon = strchr(size_key, ':');
                                            if (!size_colon) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad size"; break; }
                                            unsigned long long chunk_size_val = strtoull(size_colon + 1, NULL, 10);
                                            if (chunk_size_val == 0) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="size=0"; break; }

                                            const char* q1 = strchr(hash_key, '"');
                                            if (!q1) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad hash"; break; }
                                            const char* q2 = strchr(q1 + 1, '"');
                                            if (!q2) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad hash"; break; }
                                            const char* q3 = strchr(q2 + 1, '"');
                                            if (!q3) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad hash"; break; }
                                            const char* q4 = strchr(q3 + 1, '"');
                                            if (!q4) { hard_fail = 1; fail_code="E_PROTO"; fail_msg="bad hash"; break; }

                                            size_t hash_len = (size_t)(q4 - (q3 + 1));
                                            if (hash_len == 0 || hash_len >= BLAKE3_OUT_LEN * 2 + 1) {
                                                hard_fail = 1; fail_code="E_PROTO"; fail_msg="invalid hash length";
                                                break;
                                            }

                                            char chunk_hash_hex[BLAKE3_OUT_LEN * 2 + 1];
                                            memcpy(chunk_hash_hex, q3 + 1, hash_len);
                                            chunk_hash_hex[hash_len] = '\0';

                                            p = q4 + 1;

                                            if (hash_len < 4) {
                                                hard_fail = 1; fail_code="E_PROTO"; fail_msg="hash too short";
                                                break;
                                            }

                                            char dir1[64], dir2[80], block_path[160];
                                            snprintf(dir1, sizeof(dir1), "blocks/%.2s", chunk_hash_hex);
                                            snprintf(dir2, sizeof(dir2), "%s/%.2s", dir1, chunk_hash_hex + 2);
                                            snprintf(block_path, sizeof(block_path), "%s/%s", dir2, chunk_hash_hex);

                                            FILE* bf = fopen(block_path, "rb");
                                            if (!bf) {
                                                perror("fopen block for download");
                                                hard_fail = 1; fail_code="E_NOT_FOUND"; fail_msg="block not found";
                                                break;
                                            }

                                            if (chunk_size_val > 1024ULL * 1024ULL) {
                                                fclose(bf);
                                                hard_fail = 1; fail_code="E_PROTO"; fail_msg="chunk_size too large";
                                                break;
                                            }

                                            uint8_t* chunk_buf = (uint8_t*)malloc((size_t)chunk_size_val);
                                            if (!chunk_buf) {
                                                perror("malloc chunk_buf");
                                                fclose(bf);
                                                hard_fail = 1; fail_code="E_BUSY"; fail_msg="out of memory";
                                                break;
                                            }

                                            size_t rb = fread(chunk_buf, 1, (size_t)chunk_size_val, bf);
                                            fclose(bf);
                                            if (rb != (size_t)chunk_size_val) {
                                                free(chunk_buf);
                                                hard_fail = 1; fail_code="E_PROTO"; fail_msg="short read block";
                                                break;
                                            }

                                            if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                                                free(chunk_buf);
                                                hard_fail = 1; fail_code="E_PROTO"; fail_msg="unsupported verify hash";
                                                break;
                                            }

                                            blake3_hasher verify_hasher;
                                            blake3_hasher_init(&verify_hasher);
                                            blake3_hasher_update(&verify_hasher, chunk_buf, (size_t)chunk_size_val);

                                            uint8_t verify_digest[BLAKE3_OUT_LEN];
                                            blake3_hasher_finalize(&verify_hasher, verify_digest, BLAKE3_OUT_LEN);

                                            char verify_hex[BLAKE3_OUT_LEN * 2 + 1];
                                            static const char hex_digits2[] = "0123456789abcdef";
                                            for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                                                verify_hex[2 * i]     = hex_digits2[verify_digest[i] >> 4];
                                                verify_hex[2 * i + 1] = hex_digits2[verify_digest[i] & 0x0F];
                                            }
                                            verify_hex[BLAKE3_OUT_LEN * 2] = '\0';

                                            if (strcmp(verify_hex, chunk_hash_hex) != 0) {
                                                free(chunk_buf);
                                                hard_fail = 1; fail_code="E_HASH_MISMATCH"; fail_msg="chunk verification failed";
                                                break;
                                            }

                                            if (send_frame(cfd, chunk_op, chunk_buf, (uint32_t)chunk_size_val) < 0) {
                                                perror("send_frame download chunk");
                                                free(chunk_buf);
                                                hard_fail = 1; fail_code="E_BUSY"; fail_msg="send failed";
                                                break;
                                            }

                                            free(chunk_buf);
                                        }

                                        if (hard_fail) {
                                            send_error(proto, cfd, (proto == PROTO_GW ? done_op : 0), fail_code, fail_msg);
                                            if (proto == PROTO_PDF) send_frame(cfd, done_op, NULL, 0);
                                        } else {
                                            send_frame(cfd, done_op, NULL, 0);
                                        }

                                        free(manifest);
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } else {
            /* unknown op: treat as protocol error */
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
