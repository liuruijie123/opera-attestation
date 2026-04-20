import math
import hashlib
from typing import List


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

    def _get_hash_values(self, element: bytes) -> List[int]:

        h1 = int.from_bytes(hashlib.sha256(element).digest()[:8], 'big')
        h2 = int.from_bytes(hashlib.md5(element).digest()[:8], 'big')
        indices = []
        for i in range(self.k):
            combined = (h1 + i * h2) % self.m
            indices.append(combined)
        return indices

    def _set_bit(self, idx: int) -> None:
        
        byte_idx = idx // 8
        bit_idx = idx % 8
        self.bits[byte_idx] |= (1 << bit_idx)

    def _get_bit(self, idx: int) -> bool:
       
        byte_idx = idx // 8
        bit_idx = idx % 8
        return (self.bits[byte_idx] >> bit_idx) & 1 == 1

    def add(self, element: bytes) -> None:
        
        for idx in self._get_hash_values(element):
            self._set_bit(idx)

    def __contains__(self, element: bytes) -> bool:
        
        for idx in self._get_hash_values(element):
            if not self._get_bit(idx):
                return False
        return True

    def query(self, element: bytes) -> bool:
        
        return element in self

    def to_bytes(self) -> bytes:
        
        return bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes, expected_elements: int, false_positive_rate: float):
        
        bf = cls(expected_elements, false_positive_rate)
        expected_len = (bf.m + 7) // 8
        if len(data) < expected_len:
            raise ValueError(f"Insufficient data length: expected {expected_len} bytes, got {len(data)}")
        bf.bits = bytearray(data[:expected_len])
        return bf

    def __repr__(self) -> str:
        return (f"BloomFilter(expected={self.n}, fpr={self.p}, "
                f"m={self.m}, k={self.k}, bytes={len(self.bits)})")


