#!/usr/bin/env python3
# opera_protocol_multiprocess.py - 轻量级并行优化版（仅并行化叶子节点操作）

import os
import time
import random
import math
from typing import List, Optional, Dict, Any
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# 直接复用原有模块
from bloom_filter import BloomFilter
from crcs import CRCS
from token_issuance import NetworkOwner, Verifier, Token

# ------------------------------ 聚合树节点（与原版相同）-----------------------------
class TreeNode:
    def __init__(self, node_id: str, parent=None):
        self.id = node_id
        self.parent = parent
        self.children = []
        self.is_aggregator = False
        self.sk = None
        self.pk = None
        self.config = None
        self.good_bf = None
        self.r = None
        self.R = None
        self.R_A = None
        self.challenge = None
        self.token = None
        self.nonce = None

def build_quadtree(num_leaves: int, branch_factor: int = 4):
    depth = math.ceil(math.log(num_leaves, branch_factor))
    counter = 0
    def build(level, parent):
        nonlocal counter
        node_id = f"n{counter}"
        counter += 1
        node = TreeNode(node_id, parent)
        if level == depth:
            node.is_aggregator = False
        else:
            node.is_aggregator = True
            for _ in range(branch_factor):
                child = build(level+1, node)
                node.children.append(child)
        return node
    root = build(0, None)
    return root

# ------------------------------ 并行辅助函数（用于叶子节点）-----------------------------
def _init_leaf_data(good_bf_bytes, mal_ratio):
    """
    在子进程中生成单个叶子的密钥、配置。
    注意：good_bf_bytes 是 BloomFilter 的序列化字节，子进程需要反序列化。
    """
    # 重新创建 CRCS 和 BloomFilter 实例（因为原对象不可序列化）
    crcs = CRCS()
    good_bf = BloomFilter.from_bytes(good_bf_bytes, expected_elements=3, false_positive_rate=0.001)
    sk, pk = crcs.kgen()
    good_configs = [b"v1.0", b"v1.1", b"v2.0"]
    if random.random() < (1 - mal_ratio):
        config = random.choice(good_configs)
    else:
        config = b"bad_" + os.urandom(4).hex().encode()
    return sk, pk, config

def assign_keys_and_configs_parallel(root, good_bf, crcs, mal_ratio=0.3, max_workers=None):
    """并行分配密钥和配置（仅叶子节点）"""
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)
    good_bf_bytes = good_bf.to_bytes()
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_init_leaf_data, good_bf_bytes, mal_ratio) for _ in leaves]
        for leaf, future in zip(leaves, futures):
            sk, pk, config = future.result()
            leaf.sk = sk
            leaf.pk = pk
            leaf.config = config
            leaf.good_bf = good_bf  # 共享同一个对象（主进程中）

def broadcast_challenge(node, challenge):
    node.challenge = challenge
    for ch in node.children:
        broadcast_challenge(ch, challenge)

def collect_commitments(node, crcs):
    """单线程收集承诺（与原版相同）"""
    if not node.is_aggregator:
        r, R = crcs.cgen()
        node.r = r
        node.R = R
        return R
    else:
        child_Rs = []
        for ch in node.children:
            Rc = collect_commitments(ch, crcs)
            if Rc is not None:
                child_Rs.append(Rc)
        if child_Rs:
            R_A = crcs.acom(child_Rs)
            node.R = R_A
            return R_A
        return None

def broadcast_aggregated_commitment(node, R_A):
    node.R_A = R_A
    for ch in node.children:
        broadcast_aggregated_commitment(ch, R_A)

def set_token_and_nonce(node, token, nonce):
    node.token = token
    node.nonce = nonce
    for ch in node.children:
        set_token_and_nonce(ch, token, nonce)

def _leaf_partial_signature(sk, r, R_A, config, good_bf_bytes, nonce, M):
    """在子进程中生成单个叶子的部分签名"""
    crcs = CRCS()
    good_bf = BloomFilter.from_bytes(good_bf_bytes, expected_elements=3, false_positive_rate=0.001)
    if config in good_bf:
        msg = M
    else:
        bf_self = BloomFilter(1, 0.001)
        bf_self.add(config)
        msg = bf_self.to_bytes() + nonce
    tau, D = crcs.psign(sk, r, R_A, msg, M)
    return tau, D

def collect_partial_signatures(node, M, crcs):
    """收集部分签名：叶子节点可并行，内部节点顺序聚合"""
    if not node.is_aggregator:
        # 单线程模式（因为我们已经将并行化放在更上层？这里保持简单，不并行）
        if node.config in node.good_bf:
            msg = M
        else:
            bf_self = BloomFilter(1, 0.001)
            bf_self.add(node.config)
            msg = bf_self.to_bytes() + node.nonce
        tau, D = crcs.psign(node.sk, node.r, node.R_A, msg, M)
        return [(tau, D)]
    else:
        child_partials = []
        for ch in node.children:
            child_partials.extend(collect_partial_signatures(ch, M, crcs))
        if child_partials:
            tau_agg, D_agg = crcs.sign(child_partials)
            return [(tau_agg, D_agg)]
        return []

def collect_public_keys(node, out_list):
    if not node.is_aggregator:
        out_list.append(node.pk)
    else:
        for ch in node.children:
            collect_public_keys(ch, out_list)

# ------------------------------ 协议主函数 ------------------------------
def initialize_protocol(num_leaves, branch, mal_ratio, good_configs_list=None, max_workers=None):
    crcs = CRCS()
    if good_configs_list is None:
        good_configs_list = [b"v1.0", b"v1.1", b"v2.0"]
    good_bf = BloomFilter(len(good_configs_list), 0.001)
    for cfg in good_configs_list:
        good_bf.add(cfg)
    root = build_quadtree(num_leaves, branch)
    assign_keys_and_configs_parallel(root, good_bf, crcs, mal_ratio, max_workers)
    all_pks = []
    collect_public_keys(root, all_pks)
    apk = crcs.apk(all_pks)
    apk_bytes = crcs._point_to_bytes(apk)
    device_ids = [f"dev_{i}" for i in range(num_leaves)]
    owner = NetworkOwner()
    verifier = Verifier()
    token = verifier.request_token(
        owner, expiry_duration=1800,
        good_configs_list=good_configs_list,
        apk_bytes=apk_bytes,
        device_ids=device_ids
    )
    if token is None:
        raise RuntimeError("Token issuance failed")
    return {
        'crcs': crcs,
        'root': root,
        'apk': apk,
        'token': token,
        'good_bf': good_bf,
        'good_configs_list': good_configs_list,
        'num_leaves': num_leaves,
        'branch': branch,
        'mal_ratio': mal_ratio
    }

def run_online_attestation(ctx, verbose=False, return_metrics=False):
    crcs = ctx['crcs']
    root = ctx['root']
    apk = ctx['apk']
    token = ctx['token']
    nonce = os.urandom(32)
    M = b"default_" + nonce + token.counter_value.to_bytes(8, 'big')
    set_token_and_nonce(root, token, nonce)
    start_time = time.time()
    broadcast_challenge(root, nonce)
    R_A = collect_commitments(root, crcs)
    broadcast_aggregated_commitment(root, R_A)
    partials = collect_partial_signatures(root, M, crcs)
    tau_agg, D_agg = partials[0]
    end_time = time.time()
    elapsed_ms = (end_time - start_time) * 1000.0
    valid, result_D = crcs.vrfy(apk, (tau_agg, D_agg), M, R_A, S_perp=[])
    sig_size = 32
    for msg, pk_list in D_agg.items():
        sig_size += len(msg) + len(pk_list) * 32
    anomalous_count = sum(len(pks) for pks in result_D.values()) if valid else 0
    if verbose:
        print(f"Verification result: {valid}")
        if valid:
            print(f"Anomalous devices count: {anomalous_count}")
        else:
            print("Signature invalid!")
        print(f"Online attestation time: {elapsed_ms:.2f} ms")
    if return_metrics:
        return {
            'time_ms': elapsed_ms,
            'sig_size_bytes': sig_size,
            'anomalous_count': anomalous_count,
            'valid': valid
        }
    else:
        return elapsed_ms

def run_full_attestation(num_leaves=16, branch=4, mal_ratio=0.3, verbose=True, return_metrics=False, max_workers=None):
    # 计时初始化
    init_start = time.time()
    ctx = initialize_protocol(num_leaves, branch, mal_ratio, max_workers=max_workers)
    init_time = (time.time() - init_start) * 1000.0

    # 计时在线认证
    online_result = run_online_attestation(ctx, verbose=False, return_metrics=True)
    online_time = online_result['time_ms']

    if verbose:
        print(f"Initialization time: {init_time:.2f} ms")
        print(f"Online attestation time: {online_time:.2f} ms")
        print(f"Verification result: {online_result['valid']}")
        print(f"Anomalous devices count: {online_result['anomalous_count']}")

    if return_metrics:
        return {
            'init_time_ms': init_time,
            'online_time_ms': online_time,
            'sig_size_bytes': online_result['sig_size_bytes'],
            'anomalous_count': online_result['anomalous_count'],
            'valid': online_result['valid']
        }
    else:
        return online_time  # 保持向后兼容

if __name__ == "__main__":
    max_workers = multiprocessing.cpu_count()
    print(f"Using {max_workers} workers for key generation")
    result = run_full_attestation(num_leaves=1024, branch=4, mal_ratio=0, verbose=True, return_metrics=True, max_workers=max_workers)
    print("\n=== Summary ===")
    print(f"Init time: {result['init_time_ms']:.2f} ms")
    print(f"Online time: {result['online_time_ms']:.2f} ms")
    print(f"Signature size: {result['sig_size_bytes']} bytes")
    print(f"Anomalous count: {result['anomalous_count']}")