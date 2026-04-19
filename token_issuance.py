# token_issuance.py
import os
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

from bloom_filter import BloomFilter

# ----------------------------- 辅助函数 -----------------------------
def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pub_key) -> bytes:
    return pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def deserialize_ed25519_public_key(data: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(data)

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message)

def verify_signature(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False

# ----------------------------- 数据结构 -----------------------------
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

@dataclass
class TokenResponse:
    nonce: bytes                 # 原样返回验证者的 Nν
    encrypted_token: bytes
    aggregated_pk: bytes
    device_ids: List[str]
    owner_signature: bytes       # 对 (nonce || apk || ℐ) 的签名
    owner_cert: bytes

# ----------------------------- 网络所有者 O -----------------------------
class NetworkOwner:
    def __init__(self):
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.counter_pool = []
        self.next_counter_id = 1
        for _ in range(100):
            self.counter_pool.append((self.next_counter_id, 0))
            self.next_counter_id += 1

    def get_free_counter(self) -> Tuple[int, int]:
        if not self.counter_pool:
            raise RuntimeError("No free counter available")
        return self.counter_pool.pop(0)

    def generate_nonce(self) -> bytes:
        """生成随机数 N_O"""
        return os.urandom(32)

    def issue_token(self, verifier_nonce: bytes, verifier_signed_data: bytes,
                    verifier_cert: bytes, verifier_rsa_pub_der: bytes,
                    expiry_duration: int, good_configs_list: List[bytes],
                    apk_bytes: bytes, device_ids: List[str]) -> Optional[TokenResponse]:
        """
        验证者调用此方法请求令牌
        :param verifier_nonce: 验证者生成的 Nν
        :param verifier_signed_data: 验证者对 (N_O || δ_T) 的签名
        :param verifier_cert: 验证者的 Ed25519 公钥证书（字节）
        :param verifier_rsa_pub_der: 验证者的 RSA 公钥 DER（用于加密令牌）
        :param expiry_duration: 请求的有效期（秒）
        :param good_configs_list: 合法配置列表 ℋ
        :param apk_bytes: 聚合公钥 apk 字节
        :param device_ids: 设备标识符列表 ℐ
        """
        # 1. 验证验证者的签名
        # 注意：这里需要知道 N_O，但在本方法中 N_O 未传入。因此我们需要调整流程：
        # 实际应在两轮交互中，由所有者先生成 N_O 并发送给验证者，验证者再发回签名。
        # 为了简化且不破坏接口，我们让调用者将 N_O 作为参数传入。修改如下：
        # 为了清晰，我们重新设计：issue_token 需要接收 N_O 和签名。
        # 但为了与已有调用兼容，我们这里修改接口，增加 N_O 参数。
        # 下面展示修正后的接口，原接口将废弃。
        raise NotImplementedError("Use new two-step interaction")

    # 新方法：两轮交互，先返回 N_O，再接收签名请求
    def create_challenge(self, verifier_nonce: bytes) -> bytes:
        """第一轮：接收 Nν，返回 N_O"""
        return self.generate_nonce()

    def issue_token_with_challenge(self, verifier_nonce: bytes, owner_nonce: bytes,
                                   verifier_signed_data: bytes, verifier_cert: bytes,
                                   verifier_rsa_pub_der: bytes, expiry_duration: int,
                                   good_configs_list: List[bytes], apk_bytes: bytes,
                                   device_ids: List[str]) -> Optional[TokenResponse]:
        """
        第二轮：验证者发送签名后，所有者验证并签发令牌
        :param verifier_nonce: 验证者原始的 Nν
        :param owner_nonce: 所有者之前返回的 N_O
        :param verifier_signed_data: 验证者对 (owner_nonce || δ_T) 的签名
        :param verifier_cert: 验证者 Ed25519 公钥
        :param verifier_rsa_pub_der: 验证者 RSA 公钥 DER
        """
        # 验证签名
        try:
            verifier_pub = deserialize_ed25519_public_key(verifier_cert)
        except Exception:
            print("Invalid verifier certificate")
            return None
        delta_T = expiry_duration.to_bytes(8, 'big')
        expected_msg = owner_nonce + delta_T
        if not verify_signature(verifier_pub, verifier_signed_data, expected_msg):
            print("Verifier signature on (N_O || δ_T) invalid")
            return None

        # 检查有效期策略
        if expiry_duration > 3600:
            raise ValueError("Expiry duration exceeds policy limit")

        # 获取空闲计数器
        c_id, c_val = self.get_free_counter()

        # 构建合法配置 BloomFilter
        bf = BloomFilter(len(good_configs_list), 0.001)
        for cfg in good_configs_list:
            bf.add(cfg)
        bf_bytes = bf.to_bytes()

        # 创建令牌
        expiry_ts = int(time.time()) + expiry_duration
        token = Token(expiry=expiry_ts, counter_id=c_id, counter_value=c_val,
                      good_configs_bf=bf_bytes, owner_signature=b"")
        token.owner_signature = sign_message(self.private_key, token.serialize())

        # 加密令牌
        verifier_rsa_pub = serialization.load_der_public_key(verifier_rsa_pub_der)
        encrypted_token = verifier_rsa_pub.encrypt(
            token.serialize() + token.owner_signature,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )

        # 对 (verifier_nonce || apk || ℐ) 签名
        data_to_sign = verifier_nonce + apk_bytes + b''.join([id.encode() for id in device_ids])
        owner_signature2 = sign_message(self.private_key, data_to_sign)

        # 返回响应
        owner_cert = serialize_public_key(self.public_key)
        return TokenResponse(
            nonce=verifier_nonce,
            encrypted_token=encrypted_token,
            aggregated_pk=apk_bytes,
            device_ids=device_ids,
            owner_signature=owner_signature2,
            owner_cert=owner_cert
        )

# ----------------------------- 验证者 ν -----------------------------
class Verifier:
    def __init__(self):
        self.sign_private, self.sign_public = generate_ed25519_keypair()
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_public = self.rsa_private.public_key()

    def get_rsa_public_key_der(self) -> bytes:
        return self.rsa_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_ed25519_cert(self) -> bytes:
        """返回 Ed25519 公钥作为证书"""
        return serialize_public_key(self.sign_public)

    def request_token(self, owner: NetworkOwner, expiry_duration: int,
                      good_configs_list: List[bytes], apk_bytes: bytes,
                      device_ids: List[str]) -> Optional[Token]:
        # 第一步：生成 Nν 并发送给 Owner，获得 N_O
        Nν = os.urandom(32)
        N_O = owner.create_challenge(Nν)   # Owner 生成并返回 N_O

        # 第二步：签名 (N_O || δ_T)
        delta_T = expiry_duration.to_bytes(8, 'big')
        signed_msg = sign_message(self.sign_private, N_O + delta_T)

        # 第三步：发送签名、证书、RSA公钥等，请求令牌
        response = owner.issue_token_with_challenge(
            verifier_nonce=Nν,
            owner_nonce=N_O,
            verifier_signed_data=signed_msg,
            verifier_cert=self.get_ed25519_cert(),
            verifier_rsa_pub_der=self.get_rsa_public_key_der(),
            expiry_duration=expiry_duration,
            good_configs_list=good_configs_list,
            apk_bytes=apk_bytes,
            device_ids=device_ids
        )
        if response is None:
            print("Owner rejected token request")
            return None

        # 验证 owner 对 (Nν || apk || ℐ) 的签名
        owner_pub = deserialize_ed25519_public_key(response.owner_cert)
        data_to_verify = response.nonce + response.aggregated_pk + b''.join([id.encode() for id in response.device_ids])
        if not verify_signature(owner_pub, response.owner_signature, data_to_verify):
            print("Owner signature on aggregated data invalid")
            return None

        # 解密令牌
        try:
            plain = self.rsa_private.decrypt(
                response.encrypted_token,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

        # 解析令牌和签名
        sig_len = 64
        token_serialized = plain[:-sig_len]
        token_signature = plain[-sig_len:]

        expiry = int.from_bytes(token_serialized[:8], 'big')
        c_id = int.from_bytes(token_serialized[8:12], 'big')
        c_val = int.from_bytes(token_serialized[12:20], 'big')
        bf_bytes = token_serialized[20:]

        token = Token(expiry=expiry, counter_id=c_id, counter_value=c_val,
                      good_configs_bf=bf_bytes, owner_signature=token_signature)

        # 验证令牌签名
        if not verify_signature(owner_pub, token.owner_signature, token.serialize()):
            print("Token signature invalid")
            return None

        # 检查过期
        if time.time() > token.expiry:
            print("Token expired")
            return None

        return token

