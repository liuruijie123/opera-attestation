import hashlib
import random
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

    def _neg_point(self, point):
        
        if point is None:
            return None
        return (self.order - 1) * point

    def _hash_to_scalar(self, *args) -> int:
        
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
            unique_pks = []
            seen = set()
            for pk in merged_D[msg]:
                key = self._point_to_bytes(pk)
                if key not in seen:
                    seen.add(key)
                    unique_pks.append(pk)
            merged_D[msg] = unique_pks
        return tau_sum, merged_D

    def apk(self, pk_list):
        
        apk = None
        for pk in pk_list:
            if apk is None:
                apk = pk
            else:
                apk = apk + pk
        return apk

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
            if right is None:
                right = term
            else:
                right = right + term

        for msg, pk_list in D_dict.items():
            c_msg = self._hash_to_scalar(msg, R_A)
            sum_pk = None
            for pk in pk_list:
                if sum_pk is None:
                    sum_pk = pk
                else:
                    sum_pk = sum_pk + pk
            if sum_pk is not None:
                term = c_msg * sum_pk
                if right is None:
                    right = term
                else:
                    right = right + term

       
        if right is None:
            zero_point = self.order * self.G  # 阶乘后得到无穷远点
            valid = (left == zero_point)
        else:
            valid = (left == right)

        if valid:
            return True, D_dict
        else:
            return False, None


