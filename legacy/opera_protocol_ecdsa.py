#!/usr/bin/env python3

import os
import time
import random
import math
import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any

# ------------------------------ 1. BloomFilter ------------------------------
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

    def point_to_bytes(self, point):
        return self._point_to_bytes(point)

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


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def serialize_ed25519_pub(pub) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

def deserialize_ed25519_pub(data: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(data)

def sign_ed25519(priv, msg: bytes) -> bytes:
    return priv.sign(msg)

def verify_ed25519(pub, sig: bytes, msg: bytes) -> bool:
    try:
        pub.verify(sig, msg)
        return True
    except InvalidSignature:
        return False

@dataclass
class Token:
    expiry: int
    counter_id: int
    counter_value: int
    good_configs_bf: bytes
    owner_signature: bytes

    def serialize(self) -> bytes:
        return (self.expiry.to_bytes(8, 'big') +
                self.counter_id.to_bytes(4, 'big') +
                self.counter_value.to_bytes(8, 'big') +
                self.good_configs_bf)

class NetworkOwner:
    def __init__(self):
        self.sk, self.pk = generate_ed25519_keypair()
        self.counter_pool = [(i, 0) for i in range(1, 101)]

    def get_free_counter(self):
        if not self.counter_pool:
            raise RuntimeError("No free counter")
        return self.counter_pool.pop(0)

    def create_challenge(self, verifier_nonce: bytes) -> bytes:
        return os.urandom(32)

    def issue_token(self, verifier_nonce: bytes, owner_nonce: bytes,
                    verifier_signed: bytes, verifier_cert: bytes,
                    verifier_rsa_pub_der: bytes, expiry_duration: int,
                    good_configs_list: List[bytes], apk_bytes: bytes,
                    device_ids: List[str]) -> Optional[bytes]:

        try:
            v_pub = deserialize_ed25519_pub(verifier_cert)
        except:
            return None
        delta_T = expiry_duration.to_bytes(8, 'big')
        expected = owner_nonce + delta_T
        if not verify_ed25519(v_pub, verifier_signed, expected):
            return None

        if expiry_duration > 3600:
            return None

        c_id, c_val = self.get_free_counter()
        bf = BloomFilter(len(good_configs_list), 0.001)
        for cfg in good_configs_list:
            bf.add(cfg)
        bf_bytes = bf.to_bytes()
        expiry_ts = int(time.time()) + expiry_duration
        token = Token(expiry_ts, c_id, c_val, bf_bytes, b"")
        token.owner_signature = sign_ed25519(self.sk, token.serialize())


        v_rsa_pub = serialization.load_der_public_key(verifier_rsa_pub_der)
        encrypted = v_rsa_pub.encrypt(
            token.serialize() + token.owner_signature,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )


        data = verifier_nonce + apk_bytes + b''.join(id.encode() for id in device_ids)
        sig = sign_ed25519(self.sk, data)
        cert = serialize_ed25519_pub(self.pk)

        return encrypted + sig + cert + verifier_nonce

class Verifier:
    def __init__(self):
        self.sk_ed, self.pk_ed = generate_ed25519_keypair()
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_pub = self.rsa_priv.public_key()

    def get_rsa_pub_der(self) -> bytes:
        return self.rsa_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_ed_cert(self) -> bytes:
        return serialize_ed25519_pub(self.pk_ed)

    def request_token(self, owner: NetworkOwner, expiry_duration: int,
                      good_configs_list: List[bytes], apk_bytes: bytes,
                      device_ids: List[str]) -> Optional[Token]:
        Nv = os.urandom(32)
        No = owner.create_challenge(Nv)
        delta = expiry_duration.to_bytes(8, 'big')
        sig = sign_ed25519(self.sk_ed, No + delta)
        resp = owner.issue_token(Nv, No, sig, self.get_ed_cert(),
                                 self.get_rsa_pub_der(), expiry_duration,
                                 good_configs_list, apk_bytes, device_ids)
        if resp is None:
            return None
        tail = resp[-128:]
        encrypted_token = resp[:-128]
        owner_sig = tail[:64]
        owner_cert = tail[64:96]
        nonce_back = tail[96:128]
        if nonce_back != Nv:
            return None 
        try:
            owner_pub = deserialize_ed25519_pub(owner_cert)
        except:
            return None
        data = Nv + apk_bytes + b''.join(id.encode() for id in device_ids)
        if not verify_ed25519(owner_pub, owner_sig, data):
            return None
        try:
            plain = self.rsa_priv.decrypt(
                encrypted_token,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except:
            return None
        sig_len = 64
        token_serialized = plain[:-sig_len]
        token_signature = plain[-sig_len:]
        expiry = int.from_bytes(token_serialized[:8], 'big')
        c_id = int.from_bytes(token_serialized[8:12], 'big')
        c_val = int.from_bytes(token_serialized[12:20], 'big')
        bf_bytes = token_serialized[20:]
        token = Token(expiry, c_id, c_val, bf_bytes, token_signature)
        if not verify_ed25519(owner_pub, token.owner_signature, token.serialize()):
            return None
        if time.time() > token.expiry:
            return None
        return token

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

def assign_keys_and_configs(root, good_bf, crcs, mal_ratio=0.3):
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

def broadcast_challenge(node, challenge):
    node.challenge = challenge
    for ch in node.children:
        broadcast_challenge(ch, challenge)

def collect_commitments(node, crcs):
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

def collect_public_keys(node, out_list):
    if not node.is_aggregator:
        out_list.append(node.pk)
    else:
        for ch in node.children:
            collect_public_keys(ch, out_list)


def initialize_protocol(num_leaves, branch, mal_ratio, good_configs_list=None):
    crcs = CRCS()
    if good_configs_list is None:
        good_configs_list = [b"v1.0", b"v1.1", b"v2.0"]
    good_bf = BloomFilter(len(good_configs_list), 0.001)
    for cfg in good_configs_list:
        good_bf.add(cfg)
    root = build_quadtree(num_leaves, branch)
    assign_keys_and_configs(root, good_bf, crcs, mal_ratio)
    all_pks = []
    collect_public_keys(root, all_pks)
    apk = crcs.apk(all_pks)
    apk_bytes = crcs.point_to_bytes(apk)
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
    sig_size = 32  # tau
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

def run_full_attestation(num_leaves=16, branch=4, mal_ratio=0.3, verbose=True, return_metrics=False):
    ctx = initialize_protocol(num_leaves, branch, mal_ratio)
    return run_online_attestation(ctx, verbose, return_metrics)


if __name__ == "__main__":
    result = run_full_attestation(num_leaves=16, branch=4, mal_ratio=0.3, verbose=True, return_metrics=True)
    print("\n=== Summary ===")
    print(f"Time: {result['time_ms']:.2f} ms")
    print(f"Signature size: {result['sig_size_bytes']} bytes")
    print(f"Anomalous count: {result['anomalous_count']}")
