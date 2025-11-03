# A Hybrid Post-Quantum Key Exchange Mechanism Using liboqs

**Author:** Vedant Daterao, Atharva Patil
**Affiliation:** Department of Computer Engineering 
**Email:** [your.email@example.com]  
**Date:** November 2025  

---
<style>
.two-column-layout {
  column-count: 2;
  column-gap: 2em; /* Adjust as needed for spacing between columns */
}
</style>

<div class="two-column-layout">

## Abstract

Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing security even if a way is found to defeat the encryption for all but one of the component algorithms. It is motivated by transition to post-quantum cryptography.

---

## 1. Introduction

The advent of quantum computing poses a significant threat to current public-key cryptography systems such as RSA and ECC. Post-Quantum Cryptography (PQC) provides cryptographic primitives designed to resist attacks from quantum computers.

This project implements a **hybrid key exchange** mechanism, combining:
- **Classical key exchange** using X25519 (Elliptic-Curve Diffie-Hellman)
- **Post-quantum KEM** using algorithms from **liboqs**, such as Kyber

This hybrid approach ensures backward compatibility and future-proofing, where compromise of one algorithm does not compromise the shared secret.

---

## 2. Related Work

Prior research by the Open Quantum Safe project and the NIST PQC standardization efforts have explored several lattice-based and code-based schemes. Works such as Google's **CECPQ2 experiment** and Cloudflare’s **Hybrid TLS** prototypes demonstrate the feasibility of deploying hybrid key exchanges in real-world systems.

---

## 3. Goals
The primary goal of a hybrid key exchange mechanism is to facilitate the establishment of a shared secret which remains secure as long as one of the component key exchange mechanisms remains unbroken.

-   High performance: Use of hybrid key exchange should not be prohibitively expensive in terms of computational performance. In general this will depend on the performance characteristics of the specific cryptographic algorithms used, and as such is outside the scope of this document. See [PST] for preliminary results about performance characteristics.

-   Low latency: Use of hybrid key exchange should not substantially increase the latency experienced to establish a connection. Factors affecting this may include the following.

The computational performance characteristics of the specific algorithms used. See above.

No extra round trips: Attempting to negotiate hybrid key exchange should not lead to extra round trips in any of the three hybrid-aware/non-hybrid-aware scenarios listed above.

Minimal duplicate information: Attempting to negotiate hybrid key exchange should not mean having to send multiple public keys of the same type.

The tolerance for lower performance / increased latency due to use of hybrid key exchange will depend on the context and use case of the systems and the network involved.

## 4. Key encapsulation mechanisms
This document models key agreement as key encapsulation mechanisms (KEMs), which consist of three algorithms:

-   KeyGen() -> (pk, sk): A probabilistic key generation algorithm, which generates a public key pk and a secret key sk.

-   Encaps(pk) -> (ct, ss): A probabilistic encapsulation algorithm, which takes as input a public key pk and outputs a ciphertext ct and shared secret ss.

-   Decaps(sk, ct) -> ss: A decapsulation algorithm, which takes as input a secret key sk and ciphertext ct and outputs a shared secret ss, or in some cases a distinguished error value.

## 5. Construction for hybrid key exchange

### 5.1. Negotiation
Each particular combination of algorithms in a hybrid key exchange will be represented as a NamedGroup and sent in the supported_groups extension. No internal structure or grammar is implied or required in the value of the identifier; they are simply opaque identifiers.

Each value representing a hybrid key exchange will correspond to an ordered pair of two or more algorithms. 

For the client's share, the key_exchange value contains the concatenation of the pk outputs of the corresponding KEMs' KeyGen algorithms, if that algorithm corresponds to a KEM; or the (EC)DH ephemeral key share, if that algorithm corresponds to an (EC)DH group. For the server's share, the key_exchange value contains concatenation of the ct outputs of the corresponding KEMs' Encaps algorithms, if that algorithm corresponds to a KEM; or the (EC)DH ephemeral key share, if that algorithm corresponds to an (EC)DH group.

### 5.2. Transmitting public keys and ciphertexts
This document takes the relatively simple "concatenation approach": the messages from the two or more algorithms being hybridized will be concatenated together and transmitted as a single value, to avoid having to change existing data structures. The values are directly concatenated, without any additional encoding or length fields; the representation and length of elements MUST be fixed once the algorithm is fixed.

### 5.3 Shared secret calculation
Here this document also takes a simple "concatenation approach": the two shared secrets are concatenated together and used as the shared secret in the existing TLS 1.3 key schedule. Again, this document does not add any additional structure (length fields) in the concatenation procedure: for both the traditional groups and post quantum KEMs, the shared secret output length is fixed for a specific elliptic curve or parameter set.

## 6 Algorithm Selection
|Layer|Algorithm|Library|Purpose|
|---|---|---|---|
| Classical | X25519 | libsodium | Secure key exchange using ECC |
| Post-Quantum | Kyber512 | liboqs | Lattice-based quantum-resistant KEM |
| Hashing | SHA3-256 | libcrypto | Derive uniform shared key material |

</div>