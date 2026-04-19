#!/usr/bin/env python3
# benchmark_init.py - 测量 Opera 协议初始化时间（密钥生成、树构建、令牌颁发）

import time
from legacy.opera_protocol_ecdsa import initialize_protocol

def benchmark_initialization(sizes, branch=4, mal_ratio=0.3, repeats=1):
    """
    测量不同设备数量下的初始化时间
    repeats: 重复次数（可选，取平均）
    """
    results = []
    for n in sizes:
        print(f"\n=== Initialization for {n} devices ===")
        times = []
        for i in range(repeats):
            start = time.time()
            ctx = initialize_protocol(n, branch, mal_ratio)
            elapsed = (time.time() - start) * 1000  # ms
            times.append(elapsed)
            print(f"  Run {i+1}: {elapsed:.2f} ms")
        avg = sum(times) / len(times)
        results.append({'num_devices': n, 'avg_init_time_ms': avg, 'repeats': repeats})
        print(f"  Average: {avg:.2f} ms")
    return results

if __name__ == "__main__":
    sizes = [16, 64, 256, 1024, 10000]   # 可根据需要调整
    init_results = benchmark_initialization(sizes, branch=4, mal_ratio=0.3, repeats=1)
    print("\n=== Summary ===")
    for r in init_results:
        print(f"{r['num_devices']:5d} devices: {r['avg_init_time_ms']:.2f} ms")