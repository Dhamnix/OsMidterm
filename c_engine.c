// Build: gcc -O2 -pthread -o c_engine c_engine.c blake3.c
// Run:   ./c_engine /tmp/cengine.sock

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OP_UPLOAD_START  0x01
#define OP_UPLOAD_CHUNK  0x02
#define OP_UPLOAD_FINISH 0x03
#define OP_UPLOAD_DONE   0x81

#define OP_DOWNLOAD_START 0x11
#define OP_DOWNLOAD_CHUNK 0x91
#define OP_DOWNLOAD_DONE  0x92

static const char* g_sock_path = NULL;

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
            // initialize upload state: start a fresh temporary file for this connection
            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "wb");
            if (!f) {
                perror("fopen upload start");
            } else {
                fclose(f);
            }
        } else if (op == OP_UPLOAD_CHUNK) {
            // process chunk: append payload to the temporary file for this connection
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
            // finalize DAG and compute real CID:
            // CID(file) = multibase(base32) · multicodec(manifest) · multihash(serialize(manifest))
            #include "blake3.h"

            // 1) Re-open the temporary file and hash its contents with BLAKE3
            char path[64];
            snprintf(path, sizeof(path), "upload_%d.bin", cfd);
            FILE* f = fopen(path, "rb");
            if (!f) {
                perror("fopen for hash");
                const char* cid = "CID-ERROR";
                printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                fflush(stdout);
                send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
            } else {
                blake3_hasher file_hasher;
                blake3_hasher_init(&file_hasher);

                uint8_t buf[4096];
                size_t nread;
                unsigned long long file_size = 0;
                while ((nread = fread(buf, 1, sizeof(buf), f)) > 0) {
                    blake3_hasher_update(&file_hasher, buf, nread);
                    file_size += nread;
                }
                fclose(f);

                uint8_t file_hash[BLAKE3_OUT_LEN];
                blake3_hasher_finalize(&file_hasher, file_hash, BLAKE3_OUT_LEN);

                // encode file hash as hex to embed in the manifest
                char file_hash_hex[BLAKE3_OUT_LEN * 2 + 1];
                static const char hex_digits[] = "0123456789abcdef";
                for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
                    file_hash_hex[2 * i]     = hex_digits[file_hash[i] >> 4];
                    file_hash_hex[2 * i + 1] = hex_digits[file_hash[i] & 0x0F];
                }
                file_hash_hex[BLAKE3_OUT_LEN * 2] = '\0';

                // 2) Build the manifest JSON and serialize it deterministically
                // NOTE: chunk_size and the fields must match the project PDF.
                const unsigned int chunk_size = 262144; // example: 256 KiB chunk size
                char manifest[512];
                int manifest_len = snprintf(
                    manifest,
                    sizeof(manifest),
                    "{\"version\":1,\"hash_algo\":\"blake3\",\"chunk_size\":%u,\"size\":%llu,\"root\":\"%s\"}",
                    chunk_size,
                    file_size,
                    file_hash_hex
                );
                if (manifest_len <= 0 || manifest_len >= (int)sizeof(manifest)) {
                    const char* cid = "CID-MANIFEST-ERROR";
                    printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                    fflush(stdout);
                    send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                } else {
                    // 3) Compute multihash(manifest) using BLAKE3
                    blake3_hasher man_hasher;
                    blake3_hasher_init(&man_hasher);
                    blake3_hasher_update(&man_hasher, manifest, (size_t)manifest_len);
                    uint8_t man_hash[BLAKE3_OUT_LEN];
                    blake3_hasher_finalize(&man_hasher, man_hash, BLAKE3_OUT_LEN);

                    // multihash encoding: [hash_code][digest_length][digest]
                    // TODO: set HASH_CODE_BLAKE3_256 according to the PDF's multihash table.
                    const uint8_t HASH_CODE_BLAKE3_256 = 0x1f; // placeholder
                    uint8_t multihash[2 + BLAKE3_OUT_LEN];
                    size_t multihash_len = 0;
                    multihash[multihash_len++] = HASH_CODE_BLAKE3_256;
                    multihash[multihash_len++] = (uint8_t)BLAKE3_OUT_LEN;
                    memcpy(multihash + multihash_len, man_hash, BLAKE3_OUT_LEN);
                    multihash_len += BLAKE3_OUT_LEN;

                    // 4) Prepend multicodec(manifest) as a varint prefix
                    // TODO: set CODEC_MANIFEST according to the PDF's multicodec table.
                    const uint8_t CODEC_MANIFEST = 0x71; // placeholder
                    uint8_t cid_bytes[1 + sizeof(multihash)];
                    size_t cid_bytes_len = 0;
                    cid_bytes[cid_bytes_len++] = CODEC_MANIFEST;
                    memcpy(cid_bytes + cid_bytes_len, multihash, multihash_len);
                    cid_bytes_len += multihash_len;

                    // 5) Wrap everything in multibase(base32) using the "b" prefix
                    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
                    // maximum size: 1 (multibase prefix) + base32 length + 1 (null)
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
                    cid_str[0] = 'b';          // multibase base32 prefix
                    cid_str[1 + out_idx] = '\0';

                    // Optionally rename the data file to CID for direct lookup on download
                    if (rename(path, cid_str) != 0) {
                        perror("rename to cid");
                    }

                    const char* cid = cid_str;
                    printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
                    fflush(stdout);
                    send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
                }
            }
        } else if (op == OP_DOWNLOAD_START) {
            printf("[ENGINE] DOWNLOAD_START: cid=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);
            // look up CID and stream chunks; here we assume the file name is exactly the CID string
            char cid_buf[256];
            size_t cid_len = len < sizeof(cid_buf) - 1 ? len : sizeof(cid_buf) - 1;
            memcpy(cid_buf, payload, cid_len);
            cid_buf[cid_len] = '\0';

            FILE* f = fopen(cid_buf, "rb");
            if (!f) {
                perror("fopen download");
                send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
            } else {
                uint8_t buf[256 * 1024];
                size_t read_bytes;
                while ((read_bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
                    if (send_frame(cfd, OP_DOWNLOAD_CHUNK, buf, (uint32_t)read_bytes) < 0) {
                        perror("send_frame download chunk");
                        break;
                    }
                }
                fclose(f);
                send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
            }
        } else {
        }

        free(payload);
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
        // Thread-per-connection keeps it readable for OS labs
        pthread_t th;
        pthread_create(&th, NULL, (void*(*)(void*))handle_connection, (void*)(intptr_t)cfd);
        pthread_detach(th);
    }

    close(fd);
    unlink(g_sock_path);
    return 0;
}
