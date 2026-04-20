#!/usr/bin/env python3


import time
import csv
import os
import statistics
import multiprocessing
from opera_protocol import run_full_attestation

def benchmark_scalability(sizes, repeats=3, branch=4, mal_ratio=0.0, max_workers=None):

    results = []
    for n in sizes:
        print(f"\n=== Scalability: {n} devices (mal_ratio={mal_ratio}) ===")
        times = []
        sig_sizes = []
        for i in range(repeats):
            print(f"  Run {i+1}/{repeats}...", end='', flush=True)
            metrics = run_full_attestation(
                num_leaves=n, branch=branch, mal_ratio=mal_ratio,
                verbose=False, return_metrics=True, max_workers=max_workers
            )
            times.append(metrics['online_time_ms'])
            sig_sizes.append(metrics['sig_size_bytes'])
            print(f" online={metrics['online_time_ms']:.2f}ms, sig={metrics['sig_size_bytes']}B")
        avg_time = statistics.mean(times)
        std_time = statistics.stdev(times) if len(times) > 1 else 0.0
        avg_sig = statistics.mean(sig_sizes)
        results.append({
            'num_devices': n,
            'avg_online_time_ms': avg_time,
            'std_online_time_ms': std_time,
            'avg_sig_size_bytes': avg_sig,
            'mal_ratio': mal_ratio
        })
        print(f"  Average online time: {avg_time:.2f} ± {std_time:.2f} ms, signature = {avg_sig:.0f} B")
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
    max_workers = multiprocessing.cpu_count()
    print(f"Using {max_workers} threads for parallel operations")


    sizes = [16, 64, 256, 1024, 4096]
    results = benchmark_scalability(sizes, repeats=3, branch=4, mal_ratio=0.0, max_workers=max_workers)
    save_results_to_csv(results, "scalability_all_compliant.csv")
    print("\nResults saved to results/scalability_all_compliant.csv")


    # mal_ratios = [0.0, 0.1, 0.2, 0.33]
    # for r in mal_ratios:
    #     results_mal = benchmark_scalability([1024], repeats=3, mal_ratio=r, max_workers=max_workers)
    #     save_results_to_csv(results_mal, f"malicious_{int(r*100)}.csv")
