#include <arpa/inet.h>
#include <ctype.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//
// Types
//
typedef struct {
    uint8_t pk[32];
    uint8_t sk[32];
} classical_keypair_t;

typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
} pqc_kem_keypair_t;

typedef struct {
    int sock;
    uint8_t hybrid_key[32];
    int verbose;
    const char *role;
} chat_args_t;

//
// Utils ----------------------------------------------------------------------
//
int aes_gcm_encrypt(uint8_t *key, uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag) {
    unsigned long long clen;
    crypto_aead_aes256gcm_encrypt(ciphertext, &clen, plaintext, pt_len, NULL, 0, NULL, nonce, key);
    return (int)clen;
}

int aes_gcm_decrypt(uint8_t *key, uint8_t *ciphertext, size_t ct_len, uint8_t *nonce, uint8_t *tag, uint8_t *plaintext) {
    unsigned long long plen;
    if (crypto_aead_aes256gcm_decrypt(plaintext, &plen, NULL, ciphertext, ct_len, NULL, 0, nonce, key) != 0) {
        return -1;
    }
    return (int)plen;
}

//
// Classical KEM --------------------------------------------------------------
//
classical_keypair_t generate_classical_keypair() {
    classical_keypair_t kp;
    crypto_kx_keypair(kp.pk, kp.sk);
    return kp;
}

int derive_classical_secret(classical_keypair_t *self, uint8_t *peer_pk, uint8_t *session_key) {
    // Use client session keys (server can use crypto_kx_server_session_keys)
    if (crypto_kx_client_session_keys(session_key, NULL, self->pk, self->sk, peer_pk) != 0) {
        return -1;
    }
    return 0;
}

//
// Hybrid ---------------------------------------------------------------------
//
int derive_hybrid_key(uint8_t *ss_classical, size_t c_len, uint8_t *ss_pqc, size_t p_len, uint8_t *out_key, size_t out_len) {
    uint8_t buf[c_len + p_len];
    memcpy(buf, ss_classical, c_len);
    memcpy(buf + c_len, ss_pqc, p_len);
    crypto_generichash(out_key, out_len, buf, sizeof(buf), NULL, 0);
    return 0;
}

//
// PQC KEM --------------------------------------------------------------------
//
int pqc_kem_encapsulate(pqc_kem_keypair_t *kp, uint8_t *ss, uint8_t *ct) {
    return OQS_KEM_encaps(kp->kem, ct, ss, kp->public_key);
}

int pqc_kem_decapsulate(pqc_kem_keypair_t *kp, uint8_t *ss, uint8_t *ct) {
    return OQS_KEM_decaps(kp->kem, ss, ct, kp->secret_key);
}

void pqc_kem_free(pqc_kem_keypair_t *kp) {
    if (!kp) return;
    if (kp->kem) OQS_KEM_free(kp->kem);
    if (kp->public_key) free(kp->public_key);
    if (kp->secret_key) free(kp->secret_key);
    free(kp);
}

pqc_kem_keypair_t *pqc_kem_generate() {
    pqc_kem_keypair_t *kp = malloc(sizeof(pqc_kem_keypair_t));
    if (!kp) return NULL;

    kp->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kp->kem) {
        free(kp);
        return NULL;
    }

    kp->public_key = malloc(kp->kem->length_public_key);
    kp->secret_key = malloc(kp->kem->length_secret_key);
    if (!kp->public_key || !kp->secret_key) {
        pqc_kem_free(kp);
        return NULL;
    }

    if (OQS_KEM_keypair(kp->kem, kp->public_key, kp->secret_key) != OQS_SUCCESS) {
        pqc_kem_free(kp);
        return NULL;
    }

    return kp;
}

//
// Network --------------------------------------------------------------------
//

#define BUFFER_SIZE 1024

int send_encrypted_message(int sock, uint8_t *key, const char *msg) {
    uint8_t nonce[12];
    randombytes_buf(nonce, 12);

    uint8_t ciphertext[BUFFER_SIZE];
    unsigned long long clen;
    crypto_aead_aes256gcm_encrypt(ciphertext, &clen, (uint8_t *)msg, strlen(msg), NULL, 0, NULL, nonce, key);

    uint32_t net_len = htonl(12 + clen);
    send(sock, &net_len, sizeof(net_len), 0);
    send(sock, nonce, 12, 0);
    send(sock, ciphertext, clen, 0);

    return 0;
}

ssize_t receive_encrypted_message(int sock, uint8_t *key, char *out) {
    uint32_t net_len;
    if (read(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) return -1;
    uint32_t msg_len = ntohl(net_len);
    if (msg_len < 12 || msg_len > BUFFER_SIZE) return -1;

    uint8_t nonce[12], buf[BUFFER_SIZE];
    if (read(sock, nonce, 12) != 12) return -1;
    ssize_t clen = read(sock, buf, msg_len - 12);
    if (clen <= 0) return -1;

    unsigned long long plen;
    if (crypto_aead_aes256gcm_decrypt((uint8_t *)out, &plen, NULL, buf, clen, NULL, 0, nonce, key) != 0) {
        return -1;
    }
    out[plen] = '\0';

    return plen;
}

// send messages
void *send_loop(void *arg) {
    chat_args_t *ctx = (chat_args_t *)arg;
    char input[BUFFER_SIZE];
    while (1) {
        printf("> | ");
        fflush(stdout);
        if (!fgets(input, BUFFER_SIZE, stdin)) break;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "/exit") == 0) {
            printf("[%s] Closing connection.\n", ctx->role);
            close(ctx->sock);
            break;
        }

        send_encrypted_message(ctx->sock, ctx->hybrid_key, input);
    }
    pthread_exit(NULL);
}

// receive messages
void *recv_loop(void *arg) {
    chat_args_t *ctx = (chat_args_t *)arg;
    char buf[BUFFER_SIZE];
    while (1) {
        ssize_t len = receive_encrypted_message(ctx->sock, ctx->hybrid_key, buf);
        if (len <= 0) {
            printf("\rDisconnected.\n");
            close(ctx->sock);
            pthread_exit(NULL);
        }

        printf("\r< | %s\n> | ", buf);
        fflush(stdout);
    }
    free(ctx);
    pthread_exit(NULL);
}

//
// Server ---------------------------------------------------------------------
//
void run_server(int port, int verbose) {
    int server_fd, client_sock;
    struct sockaddr_in serv_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(server_fd, 5);

    while (1) {
        client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        printf("[*] Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        if (verbose) printf("[*] Starting handshake with client\n");

        // Hybrid PQC handshake ---------------------------------------------------
        pqc_kem_keypair_t *kp = pqc_kem_generate();
        if (verbose) printf("[*] Server PQC KEM keypair generated: algorithm %s\n", kp->kem->method_name);

        send(client_sock, kp->public_key, kp->kem->length_public_key, 0);
        if (verbose) printf("[*] Server sent public key (%zu bytes)\n", kp->kem->length_public_key);

        uint8_t ss_pqc[kp->kem->length_shared_secret];
        uint8_t ciphertext_pqc[kp->kem->length_ciphertext];
        if (read(client_sock, ciphertext_pqc, kp->kem->length_ciphertext) <= 0) {
            pqc_kem_free(kp);
            close(client_sock);
            continue;
        }

        if (pqc_kem_decapsulate(kp, ss_pqc, ciphertext_pqc) != OQS_SUCCESS) {
            fprintf(stderr, "[!] PQC decapsulation failed\n");
            pqc_kem_free(kp);
            close(client_sock);
            continue;
        }

        if (verbose) printf("[*] Server PQC decapsulation done, shared secret derived (%zu bytes)\n", kp->kem->length_shared_secret);

        classical_keypair_t ckp = generate_classical_keypair();
        if (verbose) printf("[*] Server classical X25519 keypair generated\n");

        uint8_t client_pk[32];
        ssize_t n = read(client_sock, client_pk, 32);
        if (n <= 0) {
            perror("read failed");
            close(client_sock);
            continue;
        }
        send(client_sock, ckp.pk, 32, 0);

        uint8_t ss_classical[32];
        if (crypto_kx_server_session_keys(ss_classical, NULL, ckp.pk, ckp.sk, client_pk) != 0) continue;
        if (verbose) printf("[*] Server classical session key derived\n");

        uint8_t hybrid_key[32];
        derive_hybrid_key(ss_classical, sizeof(ss_classical), ss_pqc, sizeof(ss_pqc), hybrid_key, sizeof(hybrid_key));
        if (verbose) printf("[*] Hybrid key derived using PQC + classical secrets\n");

        // allocate per-client context
        chat_args_t *ctx = malloc(sizeof(chat_args_t));
        ctx->sock = client_sock;
        memcpy(ctx->hybrid_key, hybrid_key, sizeof(hybrid_key));
        ctx->verbose = verbose;
        ctx->role = "Server";

        // message threads
        pthread_t send_thread, recv_thread;
        pthread_create(&send_thread, NULL, send_loop, ctx);
        pthread_create(&recv_thread, NULL, recv_loop, ctx);

        pthread_join(send_thread, NULL);
        pthread_join(recv_thread, NULL);

        close(client_sock);
        free(ctx);
        pqc_kem_free(kp);

        if (verbose) printf("[*] Connection closed, cleaning up\n");
    }
    close(server_fd);
}

//
// Client ---------------------------------------------------------------------
//
void run_client(const char *host, int port, int verbose) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[Client] Connection failed\n");
        return;
    }
    if (verbose) printf("[*] Connected to %s:%d\n", host, port);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t server_pub[kem->length_public_key];
    if (!read(sock, server_pub, kem->length_public_key)) return;

    uint8_t ss_pqc[kem->length_shared_secret];
    uint8_t ciphertext_pqc[kem->length_ciphertext];
    OQS_KEM_encaps(kem, ciphertext_pqc, ss_pqc, server_pub);
    send(sock, ciphertext_pqc, kem->length_ciphertext, 0);
    if (verbose) printf("[*] Client PQC encapsulation done, ciphertext sent\n");

    classical_keypair_t ckp = generate_classical_keypair();
    send(sock, ckp.pk, 32, 0);
    if (verbose) printf("[*] Client classical X25519 keypair generated and sent\n");

    uint8_t server_pk[32];
    if (!read(sock, server_pk, 32)) return;

    uint8_t ss_classical[32];
    if (crypto_kx_client_session_keys(ss_classical, NULL, ckp.pk, ckp.sk, server_pk) != 0) {
        fprintf(stderr, "[!] Failed to derive classical shared key\n");
        close(sock);
        return;
    }
    if (verbose) printf("[*] Client classical session key derived\n");

    uint8_t hybrid_key[32];
    derive_hybrid_key(ss_classical, sizeof(ss_classical), ss_pqc, sizeof(ss_pqc), hybrid_key, sizeof(hybrid_key));
    if (verbose) printf("[*] Hybrid key derived using PQC + classical secrets\n");

    // allocate client context
    chat_args_t *ctx = malloc(sizeof(chat_args_t));
    ctx->sock = sock;
    memcpy(ctx->hybrid_key, hybrid_key, sizeof(hybrid_key));
    ctx->verbose = verbose;
    ctx->role = "Client";

    // message threads
    pthread_t send_thread, recv_thread;
    pthread_create(&send_thread, NULL, send_loop, ctx);
    pthread_create(&recv_thread, NULL, recv_loop, ctx);

    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

    if (verbose) printf("[*] Connection closed\n");
    close(sock);
    OQS_KEM_free(kem);
}

void print_usage(const char *progname) {
    printf("Usage:\n");
    printf("    %s [-s | -c] [-v] [-h <host>] [-p <port>]\n\n", progname);
    printf("Options:\n");
    printf("    -s              Run in server mode\n");
    printf("    -c              Run in client mode\n");
    printf("    -h <host>       Server host to connect to (default: 127.0.0.1)\n");
    printf("    -p <port>       Port number (default: 7722)\n");
    printf("    -v              Enable verbose output\n");
    printf("    -H, --help      Show this help message\n");
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    int is_server = 0;
    int is_client = 0;
    char *host = "127.0.0.1";
    int port = 7722;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            is_server = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            is_client = 1;
        } else if ((strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--host") == 0) && i + 1 < argc) {
            host = argv[++i];
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if ((is_server && is_client) || (!is_server && !is_client)) {
        fprintf(stderr, "Error: Must specify exactly one of -s (server) or -c (client)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (is_server) {
        printf("[*] Running in server mode on port %d\n", port);
        run_server(port, verbose);
    } else if (is_client) {
        printf("[*] Running in client mode, connecting to %s:%d\n", host, port);
        run_client(host, port, verbose);
    }

    return 0;
}