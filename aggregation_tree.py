import hashlib
import random
import math
import os
from typing import List, Tuple, Optional
from dataclasses import dataclass


class BloomFilter:
    def __init__(self, expected_elements: int, false_positive_rate: float):
        self.n = expected_elements
        self.p = false_positive_rate
        self.m = self._calculate_m(expected_elements, false_positive_rate)
        self.k = self._calculate_k(self.m, expected_elements)
        self.bits = bytearray((self.m + 7) // 8)

    @staticmethod
    def _calculate_m(n: int, p: float) -> int:
        if p <= 0:
            p = 1e-9
        m = -n * math.log(p) / (math.log(2) ** 2)
        return math.ceil(m)

    @staticmethod
    def _calculate_k(m: int, n: int) -> int:
        k = (m / n) * math.log(2)
        return max(1, math.ceil(k))

    def _get_hash_values(self, element: bytes):
        h1 = int.from_bytes(hashlib.sha256(element).digest()[:8], 'big')
        h2 = int.from_bytes(hashlib.md5(element).digest()[:8], 'big')
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, element: bytes):
        for idx in self._get_hash_values(element):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bits[byte_idx] |= (1 << bit_idx)

    def __contains__(self, element: bytes):
        for idx in self._get_hash_values(element):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if (self.bits[byte_idx] >> bit_idx) & 1 == 0:
                return False
        return True

    def to_bytes(self) -> bytes:
        return bytes(self.bits)


from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

class CRCS:
    def __init__(self):
        self.curve = SECP256k1
        self.G = self.curve.generator
        self.order = self.curve.order
        self.hash_func = hashlib.sha256

    def _point_to_bytes(self, point):
        if point is None:
            return b'\x00'
        x = point.x()
        y = point.y()
        return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    def _hash_to_scalar(self, *args):
        h = self.hash_func()
        for arg in args:
            if isinstance(arg, Point):
                h.update(self._point_to_bytes(arg))
            elif isinstance(arg, str):
                h.update(arg.encode())
            elif isinstance(arg, int):
                h.update(arg.to_bytes((arg.bit_length() + 7) // 8, 'big'))
            else:
                h.update(str(arg).encode())
        digest = h.digest()
        return int.from_bytes(digest, 'big') % self.order

    def kgen(self):
        sk = random.randrange(1, self.order)
        pk = sk * self.G
        return sk, pk

    def cgen(self):
        r = random.randrange(1, self.order)
        R = r * self.G
        return r, R

    def acom(self, R_list):
        R_A = None
        for R in R_list:
            if R_A is None:
                R_A = R
            else:
                R_A = R_A + R
        return R_A

    def psign(self, sk, r, R_A, msg, M):
        c_msg = self._hash_to_scalar(msg, R_A)
        tau = (r + c_msg * sk) % self.order
        if msg == M:
            D = {}
        else:
            pk = sk * self.G
            D = {msg: [pk]}
        return tau, D

    def sign(self, partials):
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
                key = self._point_to_bytes(pk)
                if key not in seen:
                    seen.add(key)
                    unique.append(pk)
            merged_D[msg] = unique
        return tau_sum, merged_D

    def apk(self, pk_list):
        apk = None
        for pk in pk_list:
            if apk is None:
                apk = pk
            else:
                apk = apk + pk
        return apk

    def _neg_point(self, point):
        if point is None:
            return None
        return (self.order - 1) * point

    def vrfy(self, apk, alpha, M, R_A, S_perp):
        tau, D_dict = alpha
        apk_M = apk
        for pk in S_perp:
            if apk_M is None:
                apk_M = self._neg_point(pk)
            else:
                apk_M = apk_M + self._neg_point(pk)
        for pk_list in D_dict.values():
            for pk in pk_list:
                if apk_M is None:
                    apk_M = self._neg_point(pk)
                else:
                    apk_M = apk_M + self._neg_point(pk)
        left = tau * self.G
        right = None if R_A is None else R_A
        c_M = self._hash_to_scalar(M, R_A)
        if apk_M is not None:
            term = c_M * apk_M
            right = term if right is None else right + term
        for msg, pk_list in D_dict.items():
            c_msg = self._hash_to_scalar(msg, R_A)
            sum_pk = None
            for pk in pk_list:
                sum_pk = pk if sum_pk is None else sum_pk + pk
            if sum_pk is not None:
                term = c_msg * sum_pk
                right = term if right is None else right + term
        if right is None:
            zero = self.order * self.G
            valid = (left == zero)
        else:
            valid = (left == right)
        return valid, D_dict


class TreeNode:
    def __init__(self, node_id: str, parent=None):
        self.node_id = node_id
        self.parent = parent
        self.children = []
        self.is_aggregator = False
        self.sk = None
        self.pk = None
        self.config = None
        self.good_bf = None   
        self.challenge = None
        self.r = None
        self.R = None
        self.R_A = None

def build_quadtree(num_leaves: int, branch_factor: int = 4):
    depth = math.ceil(math.log(num_leaves, branch_factor))
    node_counter = 0
    def create_node(level, parent):
        nonlocal node_counter
        node_id = f"n{node_counter}"
        node_counter += 1
        node = TreeNode(node_id, parent)
        if level == depth:
            node.is_aggregator = False
        else:
            node.is_aggregator = True
            for _ in range(branch_factor):
                child = create_node(level+1, node)
                node.children.append(child)
        return node
    root = create_node(0, None)
    return root

def assign_keys_and_configs(root: TreeNode, good_bf: BloomFilter, crcs: CRCS, mal_ratio: float = 0.3):
    good_configs = [b"v1.0", b"v1.1", b"v2.0"]
    def assign(node):
        if not node.is_aggregator:
            sk, pk = crcs.kgen()
            node.sk = sk
            node.pk = pk
            if random.random() < (1 - mal_ratio):
                node.config = random.choice(good_configs)
            else:
                node.config = b"bad_" + os.urandom(4).hex().encode()
            node.good_bf = good_bf
        else:
            for ch in node.children:
                assign(ch)
    assign(root)

def broadcast_challenge(node: TreeNode, challenge: bytes):
    node.challenge = challenge
    for child in node.children:
        broadcast_challenge(child, challenge)

def collect_commitments(node: TreeNode, crcs: CRCS):
    if not node.is_aggregator:
        r, R = crcs.cgen()
        node.r = r
        node.R = R
        return R
    else:
        child_Rs = []
        for child in node.children:
            R_child = collect_commitments(child, crcs)
            if R_child is not None:
                child_Rs.append(R_child)
        if child_Rs:
            R_A = crcs.acom(child_Rs)
            node.R = R_A
            return R_A
        return None
def set_token_and_nonce(node, token, nonce):
    node.token = token
    node.nonce = nonce
    for child in node.children:
        set_token_and_nonce(child, token, nonce)
def broadcast_aggregated_commitment(node: TreeNode, R_A):
    node.R_A = R_A
    for child in node.children:
        broadcast_aggregated_commitment(child, R_A)

def collect_partial_signatures(node, M, crcs):
    if not node.is_aggregator:

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

def collect_public_keys(node: TreeNode, pk_list: list):
    if not node.is_aggregator:
        pk_list.append(node.pk)
    else:
        for child in node.children:
            collect_public_keys(child, pk_list)


def run_attestation(num_leaves: int = 16, branch: int = 4):
    crcs = CRCS()

    root = build_quadtree(num_leaves, branch)

    good_configs_list = [b"config_v1", b"config_v2", b"config_v3"]
    bf_good = BloomFilter(len(good_configs_list), 0.001)
    for cfg in good_configs_list:
        bf_good.add(cfg)

    assign_keys_and_configs(root, bf_good, crcs)

    M = b"default_attestation_message"

    challenge = b"fresh_nonce_12345678"
    print("=== Starting Attestation ===")
    print("Broadcasting challenge...")
    broadcast_challenge(root, challenge)
    print("Collecting commitments...")
    R_A = collect_commitments(root, crcs)
    print(f"Aggregated commitment (R_A) = {R_A}")
    print("Broadcasting aggregated commitment...")
    broadcast_aggregated_commitment(root, R_A)
    print("Collecting partial signatures...")
    partials = collect_partial_signatures(root, M, crcs)
    tau_agg, D_agg = partials[0]  
    print("Aggregated signature ready.")

    all_pks = []
    collect_public_keys(root, all_pks)
    apk = crcs.apk(all_pks)

    valid, result_D = crcs.vrfy(apk, (tau_agg, D_agg), M, R_A, S_perp=[])
    print(f"\nVerification result: {valid}")
    if valid:
        if not result_D:
            print("All devices are compliant!")
        else:
            print("Anomalous devices found:")
            for msg, pk_list in result_D.items():
                print(f"  Message (BloomFilter bytes): {msg[:20]}...")
                for pk in pk_list:
                    pk_hex = crcs._point_to_bytes(pk).hex()[:16]
                    print(f"    Public key: {pk_hex}...")
    else:
        print("Signature invalid!")

