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
#include "blake3.h"

#define OP_UPLOAD_START  0x01
#define OP_UPLOAD_CHUNK  0x02
#define OP_UPLOAD_FINISH 0x03
#define OP_UPLOAD_DONE   0x81

#define OP_DOWNLOAD_START 0x11
#define OP_DOWNLOAD_CHUNK 0x91
#define OP_DOWNLOAD_DONE  0x92

static const char* g_sock_path = NULL;

/* hash algorithm selector for multihash & manifest */
typedef enum {
    HASH_ALGO_BLAKE3 = 1
    /* Add more algorithms here if needed */
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
            /* Multihash code for BLAKE3-256 according to spec/PDF (placeholder if needed) */
            return 0x1f;
        default:
            /* 0x00 reserved/invalid */
            return 0x00;
    }
}

ssize_t read_n(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r == 0) return 0;
        if (r < 0) { if (errno == EINTR) continue; perror("read"); return -1; }
        got += r;
    }
    return (ssize_t)got;
}

int write_all(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) { if (errno == EINTR) continue; perror("write"); return -1; }
        sent += (size_t)w;
    }
    return 0;
}

int send_frame(int fd, uint8_t op, const void* payload, uint32_t len) {
    uint8_t header[5];
    header[0] = op;
    uint32_t be_len = htonl(len);
    memcpy(header + 1, &be_len, 4);
    if (write_all(fd, header, 5) < 0) return -1;
    if (len && write_all(fd, payload, len) < 0) return -1;
    return 0;
}

void handle_connection(int cfd) {
    /* Local hash algorithm selector: change this to switch multihash + manifest hash_algo */
    const hash_algo_t HASH_ALGO = HASH_ALGO_BLAKE3;

    /* buffer to remember original uploaded filename for this connection */
    char upload_filename[256];
    upload_filename[0] = '\0';

    for (;;) {
        uint8_t header[5];
        ssize_t r = read_n(cfd, header, 5);
        if (r == 0) break;
        if (r < 0) { break; }

        uint8_t op = header[0];
        uint32_t len;
        memcpy(&len, header + 1, 4);
        len = ntohl(len);

        uint8_t* payload = NULL;
        if (len) {
            payload = (uint8_t*)malloc(len);
            if (!payload) { perror("malloc"); break; }
            if (read_n(cfd, payload, len) <= 0) { free(payload); break; }
        }

        if (op == OP_UPLOAD_START) {
            printf("[ENGINE] UPLOAD_START: name=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);

            /* remember original filename (with extension) from payload */
            size_t name_len = len < sizeof(upload_filename) - 1
                              ? len
                              : sizeof(upload_filename) - 1;
            memcpy(upload_filename, payload, name_len);
            upload_filename[name_len] = '\0';

            /* start a fresh temporary file for this connection */
            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "wb");
            if (!f) {
                perror("fopen upload start");
            } else {
                fclose(f);
            }

        } else if (op == OP_UPLOAD_CHUNK) {
            /* append payload to the temporary file for this connection */
            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "ab");
            if (!f) {
                perror("fopen upload chunk");
            } else {
                if (len > 0) {
                    size_t written = fwrite(payload, 1, len, f);
                    if (written != len) {
                        perror("fwrite upload chunk");
                    }
                }
                fclose(f);
            }

        } else if (op == OP_UPLOAD_FINISH) {
            /* finalize DAG and compute CID:
             * CID(file) = multibase(base32) · multicodec(manifest) · multihash(serialize(manifest))
             */

            /* default chunk size (bytes) – can be changed if needed */
            const unsigned int chunk_size = 262144;

            /* temporary file path for this connection */
            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);

            FILE* f = fopen(path, "rb");
            if (!f) {
                perror("fopen for manifest");
                const char* cid = "CID-ERROR";
                printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                fflush(stdout);
                send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
            } else {
                /* ensure base directories exist */
                mkdir("blocks", 0777);
                mkdir("manifests", 0777);

                /* allocate read buffer = chunk_size */
                uint8_t* buf = (uint8_t*)malloc(chunk_size);
                if (!buf) {
                    perror("malloc chunk buffer");
                    fclose(f);
                    const char* cid = "CID-MEM-ERROR";
                    printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                    fflush(stdout);
                    send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                    goto done_upload_finish;
                }

                /* build "chunks" array: [{"index": i, "size": n, "hash": "<hex>"} , ...] */
                unsigned long long total_size = 0ULL;
                unsigned int chunk_index = 0;

                char chunks_json[8192];
                size_t chunks_len = 0;
                chunks_json[0] = '\0';

                size_t nread;

                while ((nread = fread(buf, 1, chunk_size, f)) > 0) {
                    total_size += nread;

                    /* currently only BLAKE3 is implemented for chunks */
                    if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                        fprintf(stderr, "Unsupported HASH_ALGO for chunks\n");
                        fclose(f);
                        free(buf);
                        const char* cid = "CID-UNSUPPORTED-HASH";
                        printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                        fflush(stdout);
                        send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                        goto done_upload_finish;
                    }

                    /* compute BLAKE3 hash of this chunk */
                    blake3_hasher chunk_hasher;
                    blake3_hasher_init(&chunk_hasher);
                    blake3_hasher_update(&chunk_hasher, buf, nread);

                    uint8_t chunk_digest[BLAKE3_OUT_LEN];
                    blake3_hasher_finalize(&chunk_hasher, chunk_digest, BLAKE3_OUT_LEN);

                    /* convert chunk digest to hex string */
                    char chunk_hash_hex[BLAKE3_OUT_LEN * 2 + 1];
                    static const char hex_digits[] = "0123456789abcdef";
                    for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                        chunk_hash_hex[2 * i]     = hex_digits[chunk_digest[i] >> 4];
                        chunk_hash_hex[2 * i + 1] = hex_digits[chunk_digest[i] & 0x0F];
                    }
                    chunk_hash_hex[BLAKE3_OUT_LEN * 2] = '\0';

                    /* store this chunk under blocks/aa/bb/<hash> */
                    char dir1[64], dir2[80], block_path[160];
                    /* first two hex chars -> aa, next two -> bb */
                    snprintf(dir1, sizeof(dir1), "blocks/%.2s", chunk_hash_hex);
                    mkdir(dir1, 0777);

                    snprintf(dir2, sizeof(dir2), "%s/%.2s", dir1, chunk_hash_hex + 2);
                    mkdir(dir2, 0777);

                    snprintf(block_path, sizeof(block_path), "%s/%s", dir2, chunk_hash_hex);

                    /* do not rewrite if block already exists (simple dedup) */
                    FILE* bf = fopen(block_path, "rb");
                    if (bf) {
                        fclose(bf);
                    } else {
                        bf = fopen(block_path, "wb");
                        if (!bf) {
                            perror("fopen block write");
                        } else {
                            size_t bw = fwrite(buf, 1, nread, bf);
                            if (bw != nread) {
                                perror("fwrite block");
                            }
                            fclose(bf);
                        }
                    }

                    /* append JSON entry for this chunk */
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
                        /* not enough space to store full manifest; abort with error CID */
                        fclose(f);
                        free(buf);
                        const char* cid = "CID-MANIFEST-CHUNKS-TOO-LARGE";
                        printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                        fflush(stdout);
                        send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                        goto done_upload_finish;
                    }

                    memcpy(chunks_json + chunks_len, entry, (size_t)entry_len);
                    chunks_len += (size_t)entry_len;
                    chunks_json[chunks_len] = '\0';

                    ++chunk_index;
                }

                fclose(f);
                free(buf);

                /* select hash_algo name based on HASH_ALGO */
                const char* hash_algo_name = hash_algo_to_name(HASH_ALGO);

                /* use the original uploaded filename if available, otherwise fall back to temp path */
                const char* filename = (upload_filename[0] != '\0') ? upload_filename : path;

                /* build manifest JSON exactly in the required format */
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
                    const char* cid = "CID-MANIFEST-ERROR";
                    printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                    fflush(stdout);
                    send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                } else {
                    /* multihash(manifest) using selected HASH_ALGO (currently only BLAKE3 implemented) */
                    if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                        fprintf(stderr, "Unsupported HASH_ALGO for manifest multihash\n");
                        const char* cid = "CID-UNSUPPORTED-HASH";
                        printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                        fflush(stdout);
                        send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                    } else {
                        blake3_hasher man_hasher;
                        blake3_hasher_init(&man_hasher);
                        blake3_hasher_update(&man_hasher, manifest, (size_t)manifest_len);

                        uint8_t man_hash[BLAKE3_OUT_LEN];
                        blake3_hasher_finalize(&man_hasher, man_hash, BLAKE3_OUT_LEN);

                        /* multihash encoding: [hash_code][digest_length][digest] */
                        uint8_t hash_code = hash_algo_to_multihash_code(HASH_ALGO);
                        uint8_t multihash[2 + BLAKE3_OUT_LEN];
                        size_t multihash_len = 0;
                        multihash[multihash_len++] = hash_code;
                        multihash[multihash_len++] = (uint8_t)BLAKE3_OUT_LEN;
                        memcpy(multihash + multihash_len, man_hash, BLAKE3_OUT_LEN);
                        multihash_len += BLAKE3_OUT_LEN;

                        /* prepend multicodec(manifest) as a prefix */
                        const uint8_t CODEC_MANIFEST = 0x71; /* placeholder, adjust to spec if needed */
                        uint8_t cid_bytes[1 + sizeof(multihash)];
                        size_t cid_bytes_len = 0;
                        cid_bytes[cid_bytes_len++] = CODEC_MANIFEST;
                        memcpy(cid_bytes + cid_bytes_len, multihash, multihash_len);
                        cid_bytes_len += multihash_len;

                        /* multibase(base32) with 'b' prefix */
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

                        /* write manifest to manifests/<cid>.json */
                        char manifest_path[256];
                        snprintf(manifest_path, sizeof(manifest_path),
                                 "manifests/%s.json", cid_str);
                        FILE* mf = fopen(manifest_path, "wb");
                        if (!mf) {
                            perror("fopen manifest write");
                        } else {
                            size_t mw = fwrite(manifest, 1, manifest_len, mf);
                            if (mw != (size_t)manifest_len) {
                                perror("fwrite manifest");
                            }
                            fclose(mf);
                        }

                        /* temporary file no longer needed: remove it */
                        if (remove(path) != 0) {
                            perror("remove temp upload file");
                        }

                        const char* cid = cid_str;
                        printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                        fflush(stdout);
                        send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                    }
                }
            }

        done_upload_finish:
            ;

        } else if (op == OP_DOWNLOAD_START) {
            printf("[ENGINE] DOWNLOAD_START: cid=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);

            /* 1) Copy CID string */
            char cid[256];
            size_t cid_len = len < sizeof(cid) - 1 ? len : sizeof(cid) - 1;
            memcpy(cid, payload, cid_len);
            cid[cid_len] = '\0';

            /* 2) Load manifest: manifests/<cid>.json */
            char manifest_path[512];
            snprintf(manifest_path, sizeof(manifest_path), "manifests/%s.json", cid);

            FILE* mf = fopen(manifest_path, "rb");
            if (!mf) {
                perror("fopen manifest");
                send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
            } else {
                if (fseek(mf, 0, SEEK_END) != 0) {
                    perror("fseek manifest");
                    fclose(mf);
                    send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                } else {
                    long msize_l = ftell(mf);
                    if (msize_l < 0) {
                        perror("ftell manifest");
                        fclose(mf);
                        send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                    } else {
                        size_t msize = (size_t)msize_l;
                        rewind(mf);

                        char* manifest = (char*)malloc(msize + 1);
                        if (!manifest) {
                            perror("malloc manifest");
                            fclose(mf);
                            send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                        } else {
                            size_t mr = fread(manifest, 1, msize, mf);
                            fclose(mf);
                            if (mr != msize) {
                                perror("fread manifest");
                                free(manifest);
                                send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                            } else {
                                manifest[msize] = '\0';

                                /* 3) Find "chunks" array in manifest JSON */
                                const char* p = strstr(manifest, "\"chunks\"");
                                if (!p) {
                                    fprintf(stderr, "manifest has no \"chunks\" field\n");
                                    free(manifest);
                                    send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                                } else {
                                    p = strchr(p, '[');
                                    if (!p) {
                                        fprintf(stderr, "manifest has no '[' for chunks array\n");
                                        free(manifest);
                                        send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                                    } else {
                                        p++; /* move past '[' */

                                        /* 4) Iterate over chunk entries */
                                        while (1) {
                                            const char* idx_key = strstr(p, "\"index\"");
                                            if (!idx_key) {
                                                /* no more chunks */
                                                break;
                                            }

                                            const char* size_key = strstr(idx_key, "\"size\"");
                                            const char* hash_key = strstr(idx_key, "\"hash\"");
                                            if (!size_key || !hash_key) {
                                                fprintf(stderr, "chunk entry missing size or hash\n");
                                                break;
                                            }

                                            /* parse index value (for debug / ordering, not sent on wire) */
                                            const char* idx_colon = strchr(idx_key, ':');
                                            if (!idx_colon) {
                                                fprintf(stderr, "no ':' after index in chunk entry\n");
                                                break;
                                            }
                                            unsigned long index = strtoul(idx_colon + 1, NULL, 10);
                                            (void)index; /* not used in payload, just for internal logic */

                                            /* parse size value */
                                            const char* size_colon = strchr(size_key, ':');
                                            if (!size_colon) {
                                                fprintf(stderr, "no ':' after size in chunk entry\n");
                                                break;
                                            }
                                            unsigned long long chunk_size_val = strtoull(size_colon + 1, NULL, 10);
                                            if (chunk_size_val == 0) {
                                                fprintf(stderr, "chunk_size is 0 or failed to parse\n");
                                                break;
                                            }

                                            /* parse hash value: "hash":"<hex>" */
                                            const char* q1 = strchr(hash_key, '"');      /* start of "hash" */
                                            if (!q1) { fprintf(stderr, "bad hash field\n"); break; }
                                            const char* q2 = strchr(q1 + 1, '"');        /* end of "hash" */
                                            if (!q2) { fprintf(stderr, "bad hash field\n"); break; }
                                            const char* q3 = strchr(q2 + 1, '"');        /* first quote before value */
                                            if (!q3) { fprintf(stderr, "bad hash field\n"); break; }
                                            const char* q4 = strchr(q3 + 1, '"');        /* end of value */
                                            if (!q4) { fprintf(stderr, "bad hash field\n"); break; }

                                            size_t hash_len = (size_t)(q4 - (q3 + 1));
                                            if (hash_len == 0 || hash_len >= BLAKE3_OUT_LEN * 2 + 1) {
                                                fprintf(stderr, "invalid hash length in manifest\n");
                                                break;
                                            }

                                            char chunk_hash_hex[BLAKE3_OUT_LEN * 2 + 1];
                                            memcpy(chunk_hash_hex, q3 + 1, hash_len);
                                            chunk_hash_hex[hash_len] = '\0';

                                            /* move p forward so next search starts after this chunk */
                                            p = q4 + 1;

                                            /* 5) Build block path: blocks/aa/bb/<hash> */
                                            char dir1[64], dir2[80], block_path[160];
                                            if (hash_len < 4) {
                                                fprintf(stderr, "hash too short for directory scheme\n");
                                                break;
                                            }
                                            snprintf(dir1, sizeof(dir1), "blocks/%.2s", chunk_hash_hex);
                                            snprintf(dir2, sizeof(dir2), "%s/%.2s", dir1, chunk_hash_hex + 2);
                                            snprintf(block_path, sizeof(block_path), "%s/%s", dir2, chunk_hash_hex);

                                            /* 6) Read chunk from storage */
                                            FILE* bf = fopen(block_path, "rb");
                                            if (!bf) {
                                                perror("fopen block for download");
                                                break;
                                            }

                                            if (chunk_size_val > 1024ULL * 1024ULL) {
                                                /* safety limit – adjust if you use very large chunks */
                                                fprintf(stderr, "chunk_size too large\n");
                                                fclose(bf);
                                                break;
                                            }

                                            uint8_t* chunk_buf = (uint8_t*)malloc((size_t)chunk_size_val);
                                            if (!chunk_buf) {
                                                perror("malloc chunk_buf");
                                                fclose(bf);
                                                break;
                                            }

                                            size_t rb = fread(chunk_buf, 1, (size_t)chunk_size_val, bf);
                                            fclose(bf);
                                            if (rb != (size_t)chunk_size_val) {
                                                fprintf(stderr, "short read on block file\n");
                                                free(chunk_buf);
                                                break;
                                            }

                                            /* 7) Verify BLAKE3(chunk_buf) == hash in manifest
                                             * (currently verification is fixed to BLAKE3)
                                             */
                                            if (HASH_ALGO != HASH_ALGO_BLAKE3) {
                                                fprintf(stderr, "Unsupported HASH_ALGO for verify\n");
                                                free(chunk_buf);
                                                break;
                                            }

                                            blake3_hasher verify_hasher;
                                            blake3_hasher_init(&verify_hasher);
                                            blake3_hasher_update(&verify_hasher, chunk_buf, (size_t)chunk_size_val);

                                            uint8_t verify_digest[BLAKE3_OUT_LEN];
                                            blake3_hasher_finalize(&verify_hasher, verify_digest, BLAKE3_OUT_LEN);

                                            char verify_hex[BLAKE3_OUT_LEN * 2 + 1];
                                            static const char hex_digits[] = "0123456789abcdef";
                                            for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                                                verify_hex[2 * i]     = hex_digits[verify_digest[i] >> 4];
                                                verify_hex[2 * i + 1] = hex_digits[verify_digest[i] & 0x0F];
                                            }
                                            verify_hex[BLAKE3_OUT_LEN * 2] = '\0';

                                            if (strcmp(verify_hex, chunk_hash_hex) != 0) {
                                                fprintf(stderr, "chunk hash mismatch for block %s\n", block_path);
                                                free(chunk_buf);
                                                break;
                                            }

                                            /* 8) Send verified chunk to client as raw bytes */
                                            if (send_frame(cfd, OP_DOWNLOAD_CHUNK,
                                                           chunk_buf,
                                                           (uint32_t)chunk_size_val) < 0) {
                                                perror("send_frame download chunk");
                                                free(chunk_buf);
                                                break;
                                            }

                                            free(chunk_buf);
                                        } /* end while chunks */

                                        /* send final DONE frame */
                                        send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                                        free(manifest);
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } else {
            /* unknown op, ignore */
        }

        if (payload) {
            free(payload);
        }
    }

    close(cfd);
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
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        /* Thread-per-connection keeps it readable for OS labs */
        pthread_t th;
        pthread_create(&th, NULL, (void*(*)(void*))handle_connection, (void*)(intptr_t)cfd);
        pthread_detach(th);
    }

    close(fd);
    unlink(g_sock_path);
    return 0;
}
