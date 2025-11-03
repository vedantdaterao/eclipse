import oqs
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ITERATIONS = 1000

def benchmark_kyber():
    kemalg = "Kyber512"
    with oqs.KeyEncapsulation(kemalg) as client:
        with oqs.KeyEncapsulation(kemalg) as server:
            # Key generation
            start = time.time()
            for _ in range(ITERATIONS):
                server_keypair = oqs.KeyEncapsulation(kemalg)
            keygen_time = (time.time() - start) / ITERATIONS

            # Encapsulation
            start = time.time()
            for _ in range(ITERATIONS):
                ciphertext, shared_secret_client = client.encap_secret(server.public_key)
            encap_time = (time.time() - start) / ITERATIONS

            # Decapsulation
            start = time.time()
            for _ in range(ITERATIONS):
                shared_secret_server = server.decap_secret(ciphertext)
            decap_time = (time.time() - start) / ITERATIONS

            # Verify
            assert shared_secret_client == shared_secret_server

    return {
        "keygen": keygen_time,
        "encap": encap_time,
        "decap": decap_time,
        "public_key_size": len(server.public_key),
        "ciphertext_size": len(ciphertext),
        "secret_size": len(shared_secret_client)
    }

def benchmark_ecdh():
    start = time.time()
    for _ in range(ITERATIONS):
        private_key = ec.generate_private_key(ec.SECP256R1())
    keygen_time = (time.time() - start) / ITERATIONS

    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_key = ec.generate_private_key(ec.SECP256R1())
    peer_public = peer_key.public_key()

    start = time.time()
    for _ in range(ITERATIONS):
        shared_secret = private_key.exchange(ec.ECDH(), peer_public)
    derive_time = (time.time() - start) / ITERATIONS

    pub_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "keygen": keygen_time,
        "derive": derive_time,
        "public_key_size": len(pub_key_bytes),
        "secret_size": len(shared_secret)
    }

def main():
    kyber = benchmark_kyber()
    ecdh = benchmark_ecdh()

    print("\n==== Benchmark Results (avg seconds) ====")
    print("Kyber512:")
    for k,v in kyber.items():
        print(f"  {k}: {v:.6f}")

    print("\nECDH (secp256r1):")
    for k,v in ecdh.items():
        print(f"  {k}: {v:.6f}")

if __name__ == "__main__":
    main()

