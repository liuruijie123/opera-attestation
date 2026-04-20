#!/usr/bin/env python3


import os
import csv
import tracemalloc
from legacy.opera_protocol_ecdsa import initialize_protocol, run_online_attestation

def get_peak_memory_mb_tracemalloc():

    _, peak = tracemalloc.get_traced_memory()
    return peak / (1024 * 1024)

def measure_peak_memory_scalability(sizes, repeats=3, branch=4, mal_ratio=0.3):

    results = []
    for n in sizes:
        print(f"\n=== Memory scalability: {n} devices (mal_ratio={mal_ratio}) ===")
        peak_memories = []
        for i in range(repeats):
            print(f"  Run {i+1}/{repeats}...", end='', flush=True)

            tracemalloc.start()

            ctx = initialize_protocol(n, branch, mal_ratio)

            _ = run_online_attestation(ctx, verbose=False, return_metrics=False)

            peak_mb = get_peak_memory_mb_tracemalloc()
            tracemalloc.stop()
            peak_memories.append(peak_mb)
            print(f" peak={peak_mb:.2f} MB")
        avg_peak = sum(peak_memories) / len(peak_memories)
        results.append({
            'num_devices': n,
            'avg_peak_memory_mb': avg_peak,
            'repeats': repeats,
            'mal_ratio': mal_ratio
        })
        print(f"  Average peak memory: {avg_peak:.2f} MB")
    return results

def measure_peak_memory_malicious(num_devices, ratios, repeats=3, branch=4):

    results = []
    for r in ratios:
        print(f"\n=== Malicious ratio: {r*100:.0f}% (devices={num_devices}) ===")
        peak_memories = []
        for i in range(repeats):
            print(f"  Run {i+1}/{repeats}...", end='', flush=True)
            tracemalloc.start()
            ctx = initialize_protocol(num_devices, branch, r)
            _ = run_online_attestation(ctx, verbose=False, return_metrics=False)
            peak_mb = get_peak_memory_mb_tracemalloc()
            tracemalloc.stop()
            peak_memories.append(peak_mb)
            print(f" peak={peak_mb:.2f} MB")
        avg_peak = sum(peak_memories) / len(peak_memories)
        results.append({
            'num_devices': num_devices,
            'mal_ratio': r,
            'avg_peak_memory_mb': avg_peak,
            'repeats': repeats
        })
        print(f"  Average peak memory: {avg_peak:.2f} MB")
    return results

def save_results_to_csv(results, filename):
    if not results:
        return
    keys = results[0].keys()
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", filename), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

if __name__ == "__main__":

    sizes = [16, 64, 256, 1024]  
    mem_results = measure_peak_memory_scalability(sizes, repeats=3, branch=4, mal_ratio=0.3)
    save_results_to_csv(mem_results, "memory_scalability.csv")
    print("\nMemory scalability results saved to results/memory_scalability.csv")


    ratios = [0.0, 0.1, 0.2, 0.33]
    mem_mal_results = measure_peak_memory_malicious(1024, ratios, repeats=3, branch=4)
    save_results_to_csv(mem_mal_results, "memory_malicious.csv")
    print("Memory malicious ratio results saved to results/memory_malicious.csv")
