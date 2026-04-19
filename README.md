# Opera: Optimistic Collective Remote Attestation

This repository contains a high‑performance Python implementation of the **Opera** protocol, as described in the paper  
**“Opera: Optimistic Collective Remote Attestation with Compromised-Resilience”**.

## Overview

Opera is a collective remote attestation protocol that remains efficient and resilient even when a fraction of devices are compromised.  
This implementation includes:

- **CRCS** – a pairing‑free aggregate signature that supports both identical and distinct messages.
- **Bloom filter compression** – to reduce communication overhead for malicious device configurations.
- **Quad‑tree aggregation** – enabling logarithmic‑depth aggregation of attestation evidence.

The code is optimized for speed using `coincurve` (C‑language bindings to libsecp256k1) and thread‑pool parallelism. It runs on a single PC and simulates large networks by building a logical quadtree.

## Relationship to the Paper

The performance evaluation in the paper was conducted on a **cluster of eight Raspberry Pi 4B devices** using `PyCryptodome` and `OpenSSL`, with logical nodes distributed across physical devices and communication over Unix sockets/Ethernet. The numbers reported in the paper (e.g., 458 ms for 10,000 devices online attestation) were obtained on that cluster.

This repository provides a **standalone, high‑performance prototype** that runs on a single PC. It uses `coincurve` (instead of pure Python `ecdsa`) and `ThreadPoolExecutor` to parallelise key generation, commitment, and signature generation. Consequently, the absolute timings differ from the paper – for example, on a modern 12‑core PC, 4096 devices (all compliant) complete online attestation in **~250 ms**, and initialisation in **~226 ms**.

Despite the environmental differences, the **scalability trends and the correctness** of the protocol remain exactly as described in the paper. Readers who wish to reproduce the original paper numbers should use the cluster setup detailed in the paper.

## Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

## Quick Start

Run a full attestation for 4096 devices (all compliant) with default settings:

```
python opera_protocol.py
```

Expected output (on a multi‑core PC):

```
Using 12 threads for parallel operations
Initialization time: 226.36 ms
Online attestation time: 250.63 ms
Verification result: True
Anomalous devices count: 0

=== Summary ===
Init time: 226.36 ms
Online time: 250.63 ms
Signature size: 32 bytes
Anomalous count: 0
```

## Performance Tuning

- The number of worker threads is set to the number of CPU cores (`multiprocessing.cpu_count()`). You can adjust `max_workers` in `run_full_attestation()` to control parallelism.
- For larger networks (e.g., 10,000 devices), increase the recursion limit if needed, or run the script on a machine with sufficient memory.

## File Descriptions

- `bloom_filter.py` – Bloom filter for configuration compression.
- `token_issuance.py` – Token issuance between verifier and network owner.
- `opera_protocol.py` – Main protocol implementation (high‑performance version).
- `benchmark.py` – Optional scalability and malicious‑ratio benchmark script.
- `requirements.txt` – List of Python dependencies.
- `legacy/` – Earlier implementations (single‑threaded `ecdsa` version and multi‑process version) for reference.

## Benchmarking (Optional)

To reproduce scalability numbers across different network sizes, run:

```
python benchmark.py
```

## License

This code is released under the MIT License. See `LICENSE` for details.

## Citation

If you use this code in your research, please cite the original Opera paper (to be published).