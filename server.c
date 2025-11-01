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

    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen))<0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // ============================
    // 1) Kyber Key Encapsulation
    // ============================
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        printf("Failed to create Kyber KEM\n");
        return 1;
    }

    uint8_t *server_pub = malloc(kem->length_public_key);
    uint8_t *server_priv = malloc(kem->length_secret_key);
    OQS_KEM_keypair(kem, server_pub, server_priv);

    // Send Kyber public key to client
    send(new_socket, server_pub, kem->length_public_key, 0);

    // Receive ciphertext from client
    uint8_t ciphertext[kem->length_ciphertext];
    read(new_socket, ciphertext, kem->length_ciphertext);

    // Decapsulate shared secret
    uint8_t ss_pqc[kem->length_shared_secret];
    OQS_KEM_decaps(kem, ss_pqc, ciphertext, server_priv);

    // ============================
    // 2) X25519 + AES-GCM (libsodium)
    // ============================
    // Generate server ephemeral X25519 key
    uint8_t server_sk[crypto_kx_SECRETKEYBYTES], server_pk[crypto_kx_PUBLICKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);

    // Send server PK to client
    send(new_socket, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

    // Receive client PK
    uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
    read(new_socket, client_pk, crypto_kx_PUBLICKEYBYTES);

    // Derive shared secret (server side)
    uint8_t ss_classical[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_server_session_keys(ss_classical, NULL, server_pk, server_sk, client_pk) != 0) {
        printf("Failed to derive classical shared secret\n");
        return 1;
    }

    // ============================
    // 3) Combine secrets (hybrid)
    // ============================
    uint8_t ikm[sizeof(ss_classical) + sizeof(ss_pqc)];
    memcpy(ikm, ss_classical, sizeof(ss_classical));
    memcpy(ikm + sizeof(ss_classical), ss_pqc, sizeof(ss_pqc));

    // Use ikm for AES-GCM symmetric encryption
    uint8_t key[32];
    crypto_generichash(key, sizeof(key), ikm, sizeof(ikm), NULL, 0);

    // ============================
    // 4) Receive encrypted message
    // ============================
    uint8_t nonce[12], ciphertext_msg[BUFFER_SIZE], tag[16];
    read(new_socket, nonce, 12);
    int msg_len = read(new_socket, ciphertext_msg, BUFFER_SIZE);
    read(new_socket, tag, 16);

    uint8_t decrypted[BUFFER_SIZE];
    if (crypto_aead_aes256gcm_decrypt(decrypted, NULL, NULL, ciphertext_msg, msg_len, NULL, 0, nonce, key) != 0) {
        printf("Decryption failed!\n");
    } else {
        printf("Received: %s\n", decrypted);
    }

    close(new_socket);
    close(server_fd);
    OQS_KEM_free(kem);
    free(server_pub);
    free(server_priv);
}

