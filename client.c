#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <sodium.h>

#define PORT 5555
#define BUFFER_SIZE 1024

int main() {
    if (sodium_init() < 0) {
        printf("Sodium init failed\n");
        return 1;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed\n");
        return -1;
    }

    // ============================
    // 1) Receive server Kyber PK
    // ============================
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t server_pub[kem->length_public_key];
    read(sock, server_pub, kem->length_public_key);

    // Encapsulate secret
    uint8_t ss_pqc[kem->length_shared_secret];
    uint8_t ciphertext[kem->length_ciphertext];
    OQS_KEM_encaps(kem, ciphertext, ss_pqc, server_pub);

    // Send ciphertext to server
    send(sock, ciphertext, kem->length_ciphertext, 0);

    // ============================
    // 2) X25519 + AES-GCM
    // ============================
    uint8_t client_sk[crypto_kx_SECRETKEYBYTES], client_pk[crypto_kx_PUBLICKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    // Receive server PK
    uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
    read(sock, server_pk, crypto_kx_PUBLICKEYBYTES);

    // Send client PK
    send(sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0);

    // Derive shared secret (client side)
    uint8_t ss_classical[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(ss_classical, NULL, client_pk, client_sk, server_pk) != 0) {
        printf("Failed to derive classical secret\n");
        return 1;
    }

    // ============================
    // 3) Combine secrets
    // ============================
    uint8_t ikm[sizeof(ss_classical) + sizeof(ss_pqc)];
    memcpy(ikm, ss_classical, sizeof(ss_classical));
    memcpy(ikm + sizeof(ss_classical), ss_pqc, sizeof(ss_pqc));

    uint8_t key[32];
    crypto_generichash(key, sizeof(key), ikm, sizeof(ikm), NULL, 0);

    // ============================
    // 4) Encrypt and send message
    // ============================
    uint8_t nonce[12];
    randombytes_buf(nonce, 12);

    char *msg = "Hello Hybrid PQC+Classical World!";
    uint8_t ciphertext_msg[BUFFER_SIZE];
    unsigned long long clen;
    crypto_aead_aes256gcm_encrypt(ciphertext_msg, &clen, (uint8_t *)msg, strlen(msg),
                                  NULL, 0, NULL, nonce, key);

    // Send nonce, ciphertext, tag
    send(sock, nonce, 12, 0);
    send(sock, ciphertext_msg, clen, 0);
    // AES-GCM tag is appended automatically by libsodium
    // If using OpenSSL, separate tag
    close(sock);
    OQS_KEM_free(kem);
}

