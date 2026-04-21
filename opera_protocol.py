#!/usr/bin/env python3
# opera_protocol_with_emulation.py

import os
import time
import random
import math
import hashlib
import threading
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

import coincurve
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

from bloom_filter import BloomFilter
from token_issuance import NetworkOwner, Verifier, Token

def _pk_to_ecdsa_point(pk: coincurve.PublicKey) -> Point:

    uncompressed = pk.format(compressed=False)
    x = int.from_bytes(uncompressed[1:33], 'big')
    y = int.from_bytes(uncompressed[33:65], 'big')
    return Point(SECP256k1.curve, x, y)

def _ecdsa_point_to_pk(pt: Point) -> coincurve.PublicKey:

    x_bytes = pt.x().to_bytes(32, 'big')
    y_bytes = pt.y().to_bytes(32, 'big')
    combined = b'\x04' + x_bytes + y_bytes
    return coincurve.PublicKey(combined)

class CRCSFastCoincurve:
    def __init__(self):
        self.order = SECP256k1.order   # 曲线阶
        self.hash_func = hashlib.sha256

    def _point_to_bytes(self, point: coincurve.PublicKey, compressed=True) -> bytes:
        if point is None:
            return b'\x00'
        return point.format(compressed=compressed)

    def _hash_to_scalar(self, *args) -> int:
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
        sk = os.urandom(32)
        pk = coincurve.PublicKey.from_secret(sk)
        return sk, pk

    def cgen(self) -> Tuple[bytes, coincurve.PublicKey]:
        r = os.urandom(32)
        R = coincurve.PublicKey.from_secret(r)
        return r, R

    def acom(self, R_list: List[coincurve.PublicKey]) -> Optional[coincurve.PublicKey]:
        if not R_list:
            return None
        total = None
        for R in R_list:
            pt = _pk_to_ecdsa_point(R)
            total = pt if total is None else total + pt
        return _ecdsa_point_to_pk(total)

    def psign(self, sk: bytes, r: bytes, R_A: coincurve.PublicKey, msg: bytes, M: bytes) -> Tuple[int, Dict]:
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
        tau_sum = 0
        merged_D = {}
        for tau, D in partials:
            tau_sum = (tau_sum + tau) % self.order
            for msg, pk_list in D.items():
                if msg not in merged_D:
                    merged_D[msg] = []
                merged_D[msg].extend(pk_list)
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
        if not pk_list:
            return None
        total = None
        for pk in pk_list:
            pt = _pk_to_ecdsa_point(pk)
            total = pt if total is None else total + pt
        return _ecdsa_point_to_pk(total)

    def _neg_point(self, pk: coincurve.PublicKey) -> coincurve.PublicKey:
        pt = _pk_to_ecdsa_point(pk)
        neg = -pt
        return _ecdsa_point_to_pk(neg)

    def _scalar_mult(self, scalar: int, point: Optional[coincurve.PublicKey] = None) -> coincurve.PublicKey:
        if point is None:
            sk_bytes = scalar.to_bytes(32, 'big')
            return coincurve.PublicKey.from_secret(sk_bytes)
        else:
            pt = _pk_to_ecdsa_point(point)
            res = scalar * pt
            return _ecdsa_point_to_pk(res)

    def _add_points(self, p1: Optional[coincurve.PublicKey], p2: Optional[coincurve.PublicKey]) -> Optional[coincurve.PublicKey]:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        pt1 = _pk_to_ecdsa_point(p1)
        pt2 = _pk_to_ecdsa_point(p2)
        return _ecdsa_point_to_pk(pt1 + pt2)

    def vrfy(self, apk: Optional[coincurve.PublicKey], alpha: Tuple[int, Dict], M: bytes, R_A: Optional[coincurve.PublicKey], S_perp: List[coincurve.PublicKey]) -> Tuple[bool, Dict]:
        tau, D_dict = alpha
        apk_M = apk
        for pk in S_perp:
            apk_M = self._add_points(apk_M, self._neg_point(pk))
        for pk_list in D_dict.values():
            for pk in pk_list:
                apk_M = self._add_points(apk_M, self._neg_point(pk))
        left = self._scalar_mult(tau)
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
        valid = (left.format(compressed=True) == right.format(compressed=True))
        return valid, D_dict


class NetworkEmulator:

    def __init__(self, delay_ms=0, jitter_ms=0, loss_rate=0.0, bandwidth_bps=None):
        self.delay_base = delay_ms / 1000.0
        self.jitter = jitter_ms / 1000.0
        self.loss_rate = loss_rate
        self.bandwidth_bps = bandwidth_bps

        self.token_bucket = bandwidth_bps if bandwidth_bps else float('inf')
        self.last_refill = time.time()
        self.lock = threading.Lock()

        self.fast_mode = (bandwidth_bps is None or bandwidth_bps > 1_000_000_000) and delay_ms == 0 and loss_rate == 0.0

    def _refill_token_bucket(self):
        if self.fast_mode:
            return
        now = time.time()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.bandwidth_bps
        with self.lock:
            self.token_bucket = min(self.bandwidth_bps, self.token_bucket + new_tokens)
            self.last_refill = now

    def _consume_tokens(self, size_bytes):
        if self.fast_mode:
            return
        needed = size_bytes
        while True:
            self._refill_token_bucket()
            with self.lock:
                if self.token_bucket >= needed:
                    self.token_bucket -= needed
                    return
                deficit = needed - self.token_bucket
            wait_time = deficit / self.bandwidth_bps
            time.sleep(wait_time)

    def send(self, data_size_bytes, dst_node=None):

        if self.fast_mode:
            return True
        if random.random() < self.loss_rate:
            return False
        self._consume_tokens(data_size_bytes)

        return True


class TreeNode:
    __slots__ = ('id', 'parent', 'children', 'is_aggregator', 'sk', 'pk', 'config',
                 'good_bf', 'r', 'R', 'R_A', 'challenge', 'token', 'nonce', 'emulator')
    def __init__(self, node_id: str, parent=None, emulator=None):
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
        self.emulator = emulator

def build_quadtree(num_leaves: int, branch_factor: int = 4, emulator=None):
    depth = math.ceil(math.log(num_leaves, branch_factor))
    counter = 0
    def build(level, parent):
        nonlocal counter
        node_id = f"n{counter}"
        counter += 1
        node = TreeNode(node_id, parent, emulator)
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

def collect_public_keys(node, out_list):
    if not node.is_aggregator:
        out_list.append(node.pk)
    else:
        for ch in node.children:
            collect_public_keys(ch, out_list)

def broadcast_challenge(node, challenge):
    node.challenge = challenge
    if node.emulator and node.parent:
        node.emulator.send(data_size_bytes=100, dst_node=node)
    for ch in node.children:
        broadcast_challenge(ch, challenge)

def collect_commitments_parallel(root, crcs, max_workers=None):
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(crcs.cgen): leaf for leaf in leaves}
        for future in as_completed(futures):
            leaf = futures[future]
            r, R = future.result()
            leaf.r = r
            leaf.R = R
            if leaf.emulator:
                leaf.emulator.send(data_size_bytes=33, dst_node=leaf.parent)
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
            if node.emulator and node.parent:
                node.emulator.send(data_size_bytes=33, dst_node=node.parent)
            return node.R
        return None
    return aggregate(root)

def broadcast_aggregated_commitment(node, R_A):
    node.R_A = R_A
    if node.emulator and node.parent:
        node.emulator.send(data_size_bytes=33, dst_node=node)
    for ch in node.children:
        broadcast_aggregated_commitment(ch, R_A)

def set_token_and_nonce(node, token, nonce):
    node.token = token
    node.nonce = nonce
    for ch in node.children:
        set_token_and_nonce(ch, token, nonce)

def collect_partial_signatures_parallel(root, M, crcs, max_workers=None):
    leaves = []
    def collect_leaves(node):
        if not node.is_aggregator:
            leaves.append(node)
        else:
            for ch in node.children:
                collect_leaves(ch)
    collect_leaves(root)

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
        # 估算签名大小：tau 32字节 + D 的编码大小
        sig_size = 32 + sum(len(k) + 33 for k in D.keys())
        if leaf.emulator:
            leaf.emulator.send(data_size_bytes=sig_size, dst_node=leaf.parent)
        return tau, D

    leaf_partials = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(leaf_sign, leaf): leaf for leaf in leaves}
        for future in as_completed(futures):
            leaf = futures[future]
            leaf_partials[leaf] = future.result()

    def aggregate(node):
        if not node.is_aggregator:
            return [leaf_partials[node]]
        child_partials = []
        for ch in node.children:
            child_partials.extend(aggregate(ch))
        if child_partials:
            tau_agg, D_agg = crcs.sign(child_partials)
            agg_size = 32 + sum(len(msg) + len(pks)*33 for msg, pks in D_agg.items())
            if node.emulator and node.parent:
                node.emulator.send(data_size_bytes=agg_size, dst_node=node.parent)
            return [(tau_agg, D_agg)]
        return []
    return aggregate(root)[0]

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
    sig_size = 32
    for msg, pk_list in D_agg.items():
        sig_size += len(msg) + len(pk_list) * 33
    anomalous_count = sum(len(pks) for pks in result_D.values()) if valid else 0
    if verbose:
        print(f"Verification result: {valid}")
        print(f"Anomalous devices count: {anomalous_count}")
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

def initialize_protocol(num_leaves, branch, mal_ratio, good_configs_list=None, max_workers=None, emulator=None):
    crcs = CRCSFastCoincurve()
    if good_configs_list is None:
        good_configs_list = [b"v1.0", b"v1.1", b"v2.0"]
    good_bf = BloomFilter(len(good_configs_list), 0.001)
    for cfg in good_configs_list:
        good_bf.add(cfg)
    root = build_quadtree(num_leaves, branch, emulator)
    assign_keys_and_configs_parallel(root, good_bf, crcs, mal_ratio, max_workers)
    all_pks = []
    collect_public_keys(root, all_pks)
    apk = crcs.apk(all_pks)
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

def run_full_attestation(num_leaves=16, branch=4, mal_ratio=0.3, verbose=True, return_metrics=False, max_workers=None):
    emulator = NetworkEmulator(delay_ms=5, jitter_ms=2, loss_rate=0.005, bandwidth_bps=5_000_000)
    init_start = time.time()
    ctx = initialize_protocol(num_leaves, branch, mal_ratio, max_workers=max_workers, emulator=emulator)
    init_time = (time.time() - init_start) * 1000.0
    ctx['init_time_ms'] = init_time
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
    temp_emu = NetworkEmulator(delay_ms=5, jitter_ms=2, loss_rate=0.005, bandwidth_bps=5_000_000)
    print(
        f"Using {max_workers} threads, network: {temp_emu.delay_base * 1000:.0f}ms ± {temp_emu.jitter * 1000:.0f}ms jitter, "
        f"{temp_emu.loss_rate * 100:.1f}% loss, {temp_emu.bandwidth_bps / 1e6:.1f} Mbps")
    result = run_full_attestation(num_leaves=10000, branch=4, mal_ratio=0.3, verbose=True, return_metrics=True,
                                  max_workers=max_workers)
    print(f"Init time: {result['init_time_ms']:.2f} ms")
    print(f"Online time: {result['online_time_ms']:.2f} ms")
    print(f"Anomalous count: {result['anomalous_count']}")