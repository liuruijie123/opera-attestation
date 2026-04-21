# Opera: Optimistic Collective Remote Attestation

This repository contains a high‑performance Python implementation of the **Opera** protocol, as described in the paper  
**“Opera: Optimistic Collective Remote Attestation with Compromised-Resilience”**.

## Overview

Opera is a collective remote attestation protocol that remains efficient and resilient even when a fraction of devices are compromised.  
This implementation includes:

- **CRCS** – a pairing‑free aggregate signature that supports both identical and distinct messages.
- **Bloom filter compression** – to reduce communication overhead for malicious device configurations.
- **Quad‑tree aggregation** – enabling logarithmic‑depth aggregation of attestation evidence.

The code is optimized for speed using `coincurve` (C‑language bindings to libsecp256k1) and thread‑pool parallelism. It runs on a single machine and simulates large networks by building a logical quadtree within a single process.

## Relationship to the Paper

The performance evaluation in the paper was conducted on a **single machine** using the same multi‑threaded simulation approach as this repository. A lightweight network emulation layer was applied to all inter‑node communication, introducing:

- Link bandwidth: 5 Mbps
- One‑way propagation delay: 5 ms with 2 ms jitter
- Packet loss rate: 0.5%

These parameters represent a typical mid‑range Wi‑Fi or 4G scenario. Under these conditions, the paper reports an end‑to‑end attestation time of approximately **1.1 seconds for 10,000 compliant devices**.

This repository provides a **standalone, high‑performance prototype** that can reproduce the scalability trends and correctness of the protocol. The absolute timings on your own hardware may differ from the paper due to CPU speed, memory, and operating system variations, but the relative performance across network sizes remains consistent.

## Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

## Quick Start

```
python opera_protocol.py
```

## File Descriptions

- `bloom_filter.py` – Bloom filter for configuration compression.
- `token_issuance.py` – Token issuance between verifier and network owner.
- `opera_protocol.py` – Main protocol implementation (high‑performance version).
- `benchmark.py` – Optional scalability and malicious‑ratio benchmark script.
- `requirements.txt` – List of Python dependencies.
- `legacy/` – Earlier implementations (single‑threaded `ecdsa` version and multi‑process version) for reference.

## License

This code is released under the MIT License. See `LICENSE` for details.

## Citation

If you use this code in your research, please cite the original Opera paper (to be published).