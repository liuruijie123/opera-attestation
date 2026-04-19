import math
import hashlib
from typing import List


class BloomFilter:
    """
    布隆过滤器 - 紧凑集合表示，支持假阳性率控制，无假阴性
    使用 bytearray 存储位，兼容所有平台
    """

    def __init__(self, expected_elements: int, false_positive_rate: float):
        """
        初始化布隆过滤器
        :param expected_elements: 预期插入的元素数量 (n)
        :param false_positive_rate: 目标假阳性率 (p)
        """
        self.n = expected_elements
        self.p = false_positive_rate
        # 计算最优位数组长度 m (位数)
        self.m = self._calculate_m(expected_elements, false_positive_rate)
        # 计算最优哈希函数数量 k
        self.k = self._calculate_k(self.m, expected_elements)
        # 使用 bytearray 存储位，每个字节8位
        self.bits = bytearray((self.m + 7) // 8)

    @staticmethod
    def _calculate_m(n: int, p: float) -> int:
        """计算最优位数组长度 m = ceil(-n * ln(p) / (ln(2)^2))"""
        if p <= 0:
            p = 1e-9  # 避免对数无穷大
        m = -n * math.log(p) / (math.log(2) ** 2)
        return math.ceil(m)

    @staticmethod
    def _calculate_k(m: int, n: int) -> int:
        """计算最优哈希函数数量 k = ceil((m / n) * ln(2))"""
        k = (m / n) * math.log(2)
        return max(1, math.ceil(k))

    def _get_hash_values(self, element: bytes) -> List[int]:
        """
        使用双重哈希技术生成 k 个独立的索引位置
        h_i(x) = (h1(x) + i * h2(x)) mod m
        """
        # 两个基础哈希值（取前8字节转为整数）
        h1 = int.from_bytes(hashlib.sha256(element).digest()[:8], 'big')
        h2 = int.from_bytes(hashlib.md5(element).digest()[:8], 'big')
        indices = []
        for i in range(self.k):
            combined = (h1 + i * h2) % self.m
            indices.append(combined)
        return indices

    def _set_bit(self, idx: int) -> None:
        """设置第 idx 位为 1"""
        byte_idx = idx // 8
        bit_idx = idx % 8
        self.bits[byte_idx] |= (1 << bit_idx)

    def _get_bit(self, idx: int) -> bool:
        """检查第 idx 位是否为 1"""
        byte_idx = idx // 8
        bit_idx = idx % 8
        return (self.bits[byte_idx] >> bit_idx) & 1 == 1

    def add(self, element: bytes) -> None:
        """插入元素到布隆过滤器"""
        for idx in self._get_hash_values(element):
            self._set_bit(idx)

    def __contains__(self, element: bytes) -> bool:
        """检查元素是否可能存在（假阳性允许，无假阴性）"""
        for idx in self._get_hash_values(element):
            if not self._get_bit(idx):
                return False
        return True

    def query(self, element: bytes) -> bool:
        """与 __contains__ 相同，显式方法名"""
        return element in self

    def to_bytes(self) -> bytes:
        """序列化为字节串（用于网络传输）"""
        return bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes, expected_elements: int, false_positive_rate: float):
        """从字节串反序列化"""
        bf = cls(expected_elements, false_positive_rate)
        expected_len = (bf.m + 7) // 8
        if len(data) < expected_len:
            raise ValueError(f"Insufficient data length: expected {expected_len} bytes, got {len(data)}")
        bf.bits = bytearray(data[:expected_len])
        return bf

    def __repr__(self) -> str:
        return (f"BloomFilter(expected={self.n}, fpr={self.p}, "
                f"m={self.m}, k={self.k}, bytes={len(self.bits)})")


