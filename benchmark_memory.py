#!/usr/bin/env python3
# benchmark_memory.py - 测量 Opera 协议的峰值内存消耗

import os
import csv
import tracemalloc
from legacy.opera_protocol_ecdsa import initialize_protocol, run_online_attestation

def get_peak_memory_mb_tracemalloc():
    """使用 tracemalloc 获取峰值内存（MB）"""
    # tracemalloc 必须在测量开始前启动，在测量结束后获取
    # 此函数返回当前已跟踪的峰值，需在 tracemalloc.start() 后调用
    _, peak = tracemalloc.get_traced_memory()
    return peak / (1024 * 1024)

def measure_peak_memory_scalability(sizes, repeats=3, branch=4, mal_ratio=0.3):
    """
    测量不同设备数量下的峰值内存（初始化 + 在线认证）
    返回列表，每个元素为 {'num_devices': n, 'avg_peak_memory_mb': float, ...}
    """
    results = []
    for n in sizes:
        print(f"\n=== Memory scalability: {n} devices (mal_ratio={mal_ratio}) ===")
        peak_memories = []
        for i in range(repeats):
            print(f"  Run {i+1}/{repeats}...", end='', flush=True)
            # 启动内存跟踪
            tracemalloc.start()
            # 初始化协议（这一步会分配大量内存）
            ctx = initialize_protocol(n, branch, mal_ratio)
            # 运行在线认证（也会分配临时内存）
            _ = run_online_attestation(ctx, verbose=False, return_metrics=False)
            # 获取峰值内存
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
    """
    测量不同恶意节点比例下的峰值内存
    """
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
    # 可调整规模（注意：较大规模可能内存飙升，谨慎）
    sizes = [16, 64, 256, 1024]  # 可增加 4096, 10000
    mem_results = measure_peak_memory_scalability(sizes, repeats=3, branch=4, mal_ratio=0.3)
    save_results_to_csv(mem_results, "memory_scalability.csv")
    print("\nMemory scalability results saved to results/memory_scalability.csv")

    # 恶意比例内存测试（固定 1024 设备）
    ratios = [0.0, 0.1, 0.2, 0.33]
    mem_mal_results = measure_peak_memory_malicious(1024, ratios, repeats=3, branch=4)
    save_results_to_csv(mem_mal_results, "memory_malicious.csv")
    print("Memory malicious ratio results saved to results/memory_malicious.csv")