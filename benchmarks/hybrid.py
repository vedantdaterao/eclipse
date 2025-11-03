import oqs
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# -----------------------------
# Constants / Utilities
# -----------------------------
CPU_FREQ = 3.2e9  # Approx 3.2 GHz for M1
def time_to_cycles(seconds): return seconds * CPU_FREQ

def benchmark(fn, n=100):
    """Measure average time, std, and cycles for a function over n runs."""
    times = []
    for _ in range(n):
        start = time.perf_counter_ns()
        fn()
        end = time.perf_counter_ns()
        times.append((end - start)/1e9)
    avg = np.mean(times)
    std = np.std(times)
    return avg, std, time_to_cycles(avg)

# -----------------------------
# Hybrid Key Exchange Setup
# -----------------------------

# PQC object (Kyber512)
kem = oqs.KeyEncapsulation("Kyber512")
pk_pqc = kem.generate_keypair()  # public key
ciphertext, ss_pqc = kem.encap_secret(pk_pqc)

# Classical X25519
priv_classical = x25519.X25519PrivateKey.generate()
pub_classical = priv_classical.public_key()
peer_priv = x25519.X25519PrivateKey.generate()
peer_pub = peer_priv.public_key()
ss_classical = peer_priv.exchange(pub_classical)

# Combine shared secrets via HKDF
def combine_shared(ss1, ss2):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid key exchange"
    )
    return hkdf.derive(ss1 + ss2)

# -----------------------------
# Hybrid Bench Functions
# -----------------------------

def hybrid_keygen_bench():
    """Generate both PQC and X25519 keys."""
    kem_local = oqs.KeyEncapsulation("Kyber512")
    _ = kem_local.generate_keypair()
    priv_local = x25519.X25519PrivateKey.generate()
    _ = priv_local.public_key()

def hybrid_encaps_bench():
    """Encapsulate hybrid shared secret."""
    kem_local = oqs.KeyEncapsulation("Kyber512")
    _ = kem_local.generate_keypair()  # ephemeral key
    ct, ss1 = kem.encap_secret(pk_pqc)
    priv_local = x25519.X25519PrivateKey.generate()
    pub_local = priv_local.public_key()
    ss2 = priv_local.exchange(pub_classical)
    _ = combine_shared(ss1, ss2)

def hybrid_decaps_bench():
    """Decapsulate hybrid shared secret."""
    ss1 = kem.decap_secret(ciphertext)
    ss2 = priv_classical.exchange(peer_pub)
    _ = combine_shared(ss1, ss2)

# -----------------------------
# Run Benchmarks
# -----------------------------
results = {
    "Hybrid KeyGen": benchmark(hybrid_keygen_bench),
    "Hybrid Encaps": benchmark(hybrid_encaps_bench),
    "Hybrid Decaps": benchmark(hybrid_decaps_bench),
}

# -----------------------------
# Plot CPU Cycles
# -----------------------------
labels = list(results.keys())
cycles = [r[2] for r in results.values()]
times = [r[0]*1e6 for r in results.values()]  # µs

plt.figure(figsize=(10,5))
bars = plt.bar(labels, cycles, color=['#8ecae6', '#219ebc', '#023047'])
plt.ylabel("Average CPU Cycles")
plt.title("Hybrid Kyber512 + X25519 Performance (M1 Mac)")
plt.xticks(rotation=45, ha='right')
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height*1.01,
             f"{height/1e6:.1f}M", ha='center', va='bottom', fontsize=9)
plt.tight_layout()
plt.show()

# -----------------------------
# Plot Latency (µs)
# -----------------------------
plt.figure(figsize=(10,5))
bars = plt.bar(labels, times, color=['#8ecae6', '#219ebc', '#023047'])
plt.ylabel("Average Time (µs)")
plt.title("Hybrid Kyber512 + X25519 Latency (M1 Mac)")
plt.xticks(rotation=45, ha='right')
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height*1.01,
             f"{height:.2f}", ha='center', va='bottom', fontsize=9)
plt.tight_layout()
plt.show()

# -----------------------------
# Print summary
# -----------------------------
print("\nHybrid Kyber512 + X25519 Benchmark Results:")
for name, (avg, std, cycles_val) in results.items():
    print(f"{name:<18} | {cycles_val/1e6:>7.2f} M cycles | {avg*1e6:>7.2f} µs ± {std*1e6:>6.2f}")
