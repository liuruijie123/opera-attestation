#!/usr/bin/env python3
# opera_protocol.py
# 高性能版 Opera 协议：使用 coincurve (C 绑定) + 线程池并行化

import os
import time
import random
import math
import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

import coincurve
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

# 复用原有模块
from bloom_filter import BloomFilter
from token_issuance import NetworkOwner, Verifier, Token

# ------------------------------ 1. 高性能 CRCS (基于 coincurve) ------------------------------
def _pk_to_ecdsa_point(pk: coincurve.PublicKey) -> Point:
    """将 coincurve 公钥转换为 ecdsa 点对象（用于点加法）"""
    uncompressed = pk.format(compressed=False)
    x = int.from_bytes(uncompressed[1:33], 'big')
    y = int.from_bytes(uncompressed[33:65], 'big')
    return Point(SECP256k1.curve, x, y)

def _ecdsa_point_to_pk(pt: Point) -> coincurve.PublicKey:
    """将 ecdsa 点对象转换为 coincurve 公钥"""
    x_bytes = pt.x().to_bytes(32, 'big')
    y_bytes = pt.y().to_bytes(32, 'big')
    combined = b'\x04' + x_bytes + y_bytes
    return coincurve.PublicKey(combined)

class CRCSFastCoincurve:
    """基于 coincurve 的高性能 CRCS 实现"""
    def __init__(self):
        self.order = SECP256k1.order   # 曲线阶
        self.hash_func = hashlib.sha256

    def _point_to_bytes(self, point: coincurve.PublicKey, compressed=True) -> bytes:
        """将公钥转为字节串"""
        if point is None:
            return b'\x00'
        return point.format(compressed=compressed)

    def _hash_to_scalar(self, *args) -> int:
        """将任意参数哈希后映射到 [0, order-1] 范围内的标量"""
        h = self.hash_func()
        for arg in args:
            if isinstance(arg, coincurve.PublicKey):
                h.update(self._point_to_bytes(arg, compressed=False))
            elif isinstance(arg, str):
                h.update(arg.encode())
            elif isinstance(arg, int):
                h.update(arg.to_bytes((arg.bit_length() + 7) // 8, 'big'))
            elif isinstance(arg, bytes):
                h.update(arg)
            else:
                h.update(str(arg).encode())
        digest = h.digest()
        return int.from_bytes(digest, 'big') % self.order

    def kgen(self) -> Tuple[bytes, coincurve.PublicKey]:
        """密钥生成 (sk, pk)"""
        sk = os.urandom(32)
        pk = coincurve.PublicKey.from_secret(sk)
        return sk, pk

    def cgen(self) -> Tuple[bytes, coincurve.PublicKey]:
        """承诺生成 (r, R)"""
        r = os.urandom(32)
        R = coincurve.PublicKey.from_secret(r)
        return r, R

    def acom(self, R_list: List[coincurve.PublicKey]) -> Optional[coincurve.PublicKey]:
        """承诺聚合：R_A = sum(R_i)（使用 ecdsa 点加法）"""
        if not R_list:
            return None
        total = None
        for R in R_list:
            pt = _pk_to_ecdsa_point(R)
            total = pt if total is None else total + pt
        return _ecdsa_point_to_pk(total)

    def psign(self, sk: bytes, r: bytes, R_A: coincurve.PublicKey, msg: bytes, M: bytes) -> Tuple[int, Dict]:
        """部分签名生成"""
        c_msg = self._hash_to_scalar(msg, R_A)
        sk_int = int.from_bytes(sk, 'big')
        r_int = int.from_bytes(r, 'big')
        tau = (r_int + c_msg * sk_int) % self.order
        if msg == M:
            D = {}
        else:
            pk = coincurve.PublicKey.from_secret(sk)
            D = {msg: [pk]}
        return tau, D

    def sign(self, partials: List[Tuple[int, Dict]]) -> Tuple[int, Dict]:
        """聚合部分签名"""
        tau_sum = 0
        merged_D = {}
        for tau, D in partials:
            tau_sum = (tau_sum + tau) % self.order
            for msg, pk_list in D.items():
                if msg not in merged_D:
                    merged_D[msg] = []
                merged_D[msg].extend(pk_list)
        # 去重（按公钥字节）
        for msg in merged_D:
            unique = []
            seen = set()
            for pk in merged_D[msg]:
                key = self._point_to_bytes(pk, compressed=True)
                if key not in seen:
                    seen.add(key)
                    unique.append(pk)
            merged_D[msg] = unique
        return tau_sum, merged_D

    def apk(self, pk_list: List[coincurve.PublicKey]) -> Optional[coincurve.PublicKey]:
        """聚合公钥 apk = sum(pk_i)"""
        if not pk_list:
            return None
        total = None
        for pk in pk_list:
            pt = _pk_to_ecdsa_point(pk)
            total = pt if total is None else total + pt
        return _ecdsa_point_to_pk(total)

    def _neg_point(self, pk: coincurve.PublicKey) -> coincurve.PublicKey:
        """返回公钥的负元（-pk）"""
        pt = _pk_to_ecdsa_point(pk)
        neg = -pt
        return _ecdsa_point_to_pk(neg)

    def _scalar_mult(self, scalar: int, point: Optional[coincurve.PublicKey] = None) -> coincurve.PublicKey:
        """标量乘法：scalar * G 或 scalar * point"""
        if point is None:
            # 标量乘生成元：私钥为 scalar 时公钥即为 scalar * G
            sk_bytes = scalar.to_bytes(32, 'big')
            return coincurve.PublicKey.from_secret(sk_bytes)
        else:
            # 标量乘任意点：使用 ecdsa 库
            pt = _pk_to_ecdsa_point(point)
            res = scalar * pt
            return _ecdsa_point_to_pk(res)

    def _add_points(self, p1: Optional[coincurve.PublicKey], p2: Optional[coincurve.PublicKey]) -> Optional[coincurve.PublicKey]:
        """点加法"""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        pt1 = _pk_to_ecdsa_point(p1)
        pt2 = _pk_to_ecdsa_point(p2)
        return _ecdsa_point_to_pk(pt1 + pt2)

    def vrfy(self, apk: Optional[coincurve.PublicKey], alpha: Tuple[int, Dict], M: bytes, R_A: Optional[coincurve.PublicKey], S_perp: List[coincurve.PublicKey]) -> Tuple[bool, Dict]:
        """验证聚合签名"""
        tau, D_dict = alpha
        # 计算 apk_M = apk - sum(S_perp) - sum(D_dict中的所有公钥)
        apk_M = apk
        for pk in S_perp:
            apk_M = self._add_points(apk_M, self._neg_point(pk))
        for pk_list in D_dict.values():
            for pk in pk_list:
                apk_M = self._add_points(apk_M, self._neg_point(pk))
        # 左侧：tau * G
        left = self._scalar_mult(tau)
        # 右侧：R_A + c_M * apk_M + sum(c_msg * sum(pk_in_msg))
        right = R_A
        c_M = self._hash_to_scalar(M, R_A)
        if apk_M is not None:
            right = self._add_points(right, self._scalar_mult(c_M, apk_M))
        for msg, pk_list in D_dict.items():
            c_msg = self._hash_to_scalar(msg, R_A)
            sum_pk = None
            for pk in pk_list:
                sum_pk = pk if sum_pk is None else self._add_points(sum_pk, pk)
            if sum_pk is not None:
                right = self._add_points(right, self._scalar_mult(c_msg, sum_pk))
        # 比较左右两点（使用压缩格式比较）
        valid = (left.format(compressed=True) == right.format(compressed=True))
        return valid, D_dict

# ------------------------------ 2. 聚合树节点 ------------------------------
class TreeNode:
    __slots__ = ('id', 'parent', 'children', 'is_aggregator', 'sk', 'pk', 'config',
                 'good_bf', 'r', 'R', 'R_A', 'challenge', 'token', 'nonce')
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
    """构建满四叉树，叶子节点数为 branch_factor ** depth，不小于 num_leaves"""
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

def assign_keys_and_configs_parallel(root, good_bf, crcs, mal_ratio=0.3, max_workers=None):
    """并行生成叶子节点的密钥和配置（使用线程池）"""
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)
    good_configs = [b"v1.0", b"v1.1", b"v2.0"]
    def gen_one():
        sk, pk = crcs.kgen()
        if random.random() < (1 - mal_ratio):
            config = random.choice(good_configs)
        else:
            config = b"bad_" + os.urandom(4).hex().encode()
        return sk, pk, config
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(gen_one) for _ in leaves]
        for leaf, future in zip(leaves, futures):
            sk, pk, config = future.result()
            leaf.sk = sk
            leaf.pk = pk
            leaf.config = config
            leaf.good_bf = good_bf

def broadcast_challenge(node, challenge):
    node.challenge = challenge
    for ch in node.children:
        broadcast_challenge(ch, challenge)

def collect_commitments_parallel(root, crcs, max_workers=None):
    """并行收集叶子承诺，然后顺序聚合内部节点"""
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)

    # 并行生成叶子承诺
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(crcs.cgen): leaf for leaf in leaves}
        for future in as_completed(futures):
            leaf = futures[future]
            r, R = future.result()
            leaf.r = r
            leaf.R = R

    # 自底向上聚合（顺序）
    def aggregate(node):
        if not node.is_aggregator:
            return node.R
        child_Rs = []
        for ch in node.children:
            Rc = aggregate(ch)
            if Rc is not None:
                child_Rs.append(Rc)
        if child_Rs:
            node.R = crcs.acom(child_Rs)
            return node.R
        return None
    return aggregate(root)

def broadcast_aggregated_commitment(node, R_A):
    node.R_A = R_A
    for ch in node.children:
        broadcast_aggregated_commitment(ch, R_A)

def set_token_and_nonce(node, token, nonce):
    node.token = token
    node.nonce = nonce
    for ch in node.children:
        set_token_and_nonce(ch, token, nonce)

def collect_partial_signatures_parallel(root, M, crcs, max_workers=None):
    """并行生成叶子部分签名，然后顺序聚合内部节点"""
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)

    # 并行生成叶子部分签名
    def leaf_sign(leaf):
        good_bf = leaf.good_bf
        config = leaf.config
        if config in good_bf:
            msg = M
        else:
            bf_self = BloomFilter(1, 0.001)
            bf_self.add(config)
            msg = bf_self.to_bytes() + leaf.nonce
        tau, D = crcs.psign(leaf.sk, leaf.r, leaf.R_A, msg, M)
        return tau, D

    leaf_partials = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(leaf_sign, leaf): leaf for leaf in leaves}
        for future in as_completed(futures):
            leaf = futures[future]
            leaf_partials[leaf] = future.result()

    # 自底向上聚合（顺序）
    def aggregate(node):
        if not node.is_aggregator:
            return [leaf_partials[node]]
        child_partials = []
        for ch in node.children:
            child_partials.extend(aggregate(ch))
        if child_partials:
            tau_agg, D_agg = crcs.sign(child_partials)
            return [(tau_agg, D_agg)]
        return []
    return aggregate(root)[0]  # 根节点返回聚合签名 (tau, D)

def collect_public_keys(node, out_list):
    if not node.is_aggregator:
        out_list.append(node.pk)
    else:
        for ch in node.children:
            collect_public_keys(ch, out_list)

# ------------------------------ 3. 协议主函数 ------------------------------
def initialize_protocol(num_leaves, branch, mal_ratio, good_configs_list=None, max_workers=None):
    crcs = CRCSFastCoincurve()
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
    # 序列化 apk 为字节（用于令牌）
    apk_bytes = crcs._point_to_bytes(apk, compressed=False)
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

def run_online_attestation(ctx, verbose=False, return_metrics=False, max_workers=None):
    crcs = ctx['crcs']
    root = ctx['root']
    apk = ctx['apk']
    token = ctx['token']
    nonce = os.urandom(32)
    M = b"default_" + nonce + token.counter_value.to_bytes(8, 'big')
    set_token_and_nonce(root, token, nonce)
    start_time = time.time()
    broadcast_challenge(root, nonce)
    R_A = collect_commitments_parallel(root, crcs, max_workers)
    broadcast_aggregated_commitment(root, R_A)
    tau_agg, D_agg = collect_partial_signatures_parallel(root, M, crcs, max_workers)
    end_time = time.time()
    elapsed_ms = (end_time - start_time) * 1000.0
    valid, result_D = crcs.vrfy(apk, (tau_agg, D_agg), M, R_A, S_perp=[])
    # 签名大小估算
    sig_size = 32  # tau
    for msg, pk_list in D_agg.items():
        sig_size += len(msg) + len(pk_list) * 33  # 压缩公钥 33 字节
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
    init_start = time.time()
    ctx = initialize_protocol(num_leaves, branch, mal_ratio, max_workers=max_workers)
    init_time = (time.time() - init_start) * 1000.0
    ctx['init_time_ms'] = init_time   # 存储以便返回
    online_result = run_online_attestation(ctx, verbose=False, return_metrics=True, max_workers=max_workers)
    if verbose:
        print(f"Initialization time: {init_time:.2f} ms")
        print(f"Online attestation time: {online_result['time_ms']:.2f} ms")
        print(f"Verification result: {online_result['valid']}")
        print(f"Anomalous devices count: {online_result['anomalous_count']}")
    if return_metrics:
        return {
            'init_time_ms': init_time,
            'online_time_ms': online_result['time_ms'],
            'sig_size_bytes': online_result['sig_size_bytes'],
            'anomalous_count': online_result['anomalous_count'],
            'valid': online_result['valid']
        }
    else:
        return online_result['time_ms']

if __name__ == "__main__":
    max_workers = multiprocessing.cpu_count()
    print(f"Using {max_workers} threads for parallel operations")
    # 测试 4096 设备全合规
    result = run_full_attestation(num_leaves=1024, branch=4, mal_ratio=0.1, verbose=True, return_metrics=True, max_workers=max_workers)
    print("\n=== Summary ===")
    print(f"Init time: {result['init_time_ms']:.2f} ms")
    print(f"Online time: {result['online_time_ms']:.2f} ms")
    print(f"Signature size: {result['sig_size_bytes']} bytes")
    print(f"Anomalous count: {result['anomalous_count']}")