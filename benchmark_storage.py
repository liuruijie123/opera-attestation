#!/usr/bin/env python3
# benchmark_storage.py - 测量每设备存储和总存储（轻量级数据大小）

import csv
import os
from legacy.opera_protocol_ecdsa import initialize_protocol

def measure_lightweight_storage(ctx):
    """
    测量所有叶子节点的关键数据大小（字节）
    只计算实际密码学数据，不计 Python 对象开销
    """
    root = ctx['root']
    crcs = ctx['crcs']
    good_bf = ctx['good_bf']  # 共享的布隆过滤器，不计入每个设备
    leaf_sizes = []
    total_devices = 0

    def collect(node):
        nonlocal total_devices
        if not node.is_aggregator:
            total_devices += 1
            size = 0
            # 私钥 sk: 256 位整数，通常 32 字节
            size += 32
            # 公钥 pk: 未压缩点 (x,y) 各 32 字节，共 64 字节；若压缩则为 33 字节
            # 论文中未指定，这里采用未压缩 64 字节以匹配常见实现
            size += 64
            # 配置 config: 实际存储的字节串长度
            if node.config:
                size += len(node.config)
            # 注意：good_bf 是共享的，不计入每设备
            # 其他字段（如 r, R, challenge, token, nonce）是临时变量，不应计入持久存储
            leaf_sizes.append(size)
        else:
            for ch in node.children:
                collect(ch)

    collect(root)
    if total_devices == 0:
        return 0, 0
    per_device_avg = sum(leaf_sizes) / total_devices
    total_storage = sum(leaf_sizes)
    return per_device_avg, total_storage

def benchmark_storage_scalability(sizes, branch=4, mal_ratio=0.3):
    results = []
    for n in sizes:
        print(f"Initializing {n} devices...")
        ctx = initialize_protocol(n, branch, mal_ratio)
        per_dev, total = measure_lightweight_storage(ctx)
        results.append({
            'num_devices': n,
            'per_device_bytes': per_dev,
            'total_bytes': total,
            'total_kb': total / 1024,
            'total_mb': total / (1024 * 1024)
        })
        print(f"  Per device: {per_dev:.1f} B, Total: {total/1024:.2f} KB")
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
    sizes = [16, 64, 256, 1024, 4096]  # 可根据需要调整
    storage_results = benchmark_storage_scalability(sizes, branch=4, mal_ratio=0.3)
    save_results_to_csv(storage_results, "storage_scalability.csv")
    print("\nStorage results saved to results/storage_scalability.csv")