import hashlib
import random
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

class CRCS:
    """
    Compromise-Resilience Collective Signature
    基于椭圆曲线 secp256k1 的实现，无配对运算。
    使用 None 表示无穷远点（椭圆曲线群的单位元）。
    """

    def __init__(self):
        self.curve = SECP256k1
        self.G = self.curve.generator        # 生成元
        self.order = self.curve.order        # 群的阶
        self.hash_func = hashlib.sha256

    # ---------- 辅助函数 ----------
    def _point_to_bytes(self, point):
        """将椭圆曲线点转为字节串（未压缩格式），支持 None 表示无穷远点"""
        if point is None:
            return b'\x00'                   # 无穷远点特殊编码
        x = point.x()
        y = point.y()
        return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    def _neg_point(self, point):
        """返回点的负元：-point = (order-1) * point"""
        if point is None:
            return None
        return (self.order - 1) * point

    def _hash_to_scalar(self, *args) -> int:
        """将任意参数哈希后映射到 [0, order-1] 范围内的标量"""
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

    # ---------- CRCS 算法 ----------
    def kgen(self):
        """
        密钥生成 (sk, pk) ← KGen(1^λ)
        私钥: 随机整数 x ∈ [1, order-1]
        公钥: pk = x * G
        """
        sk = random.randrange(1, self.order)
        pk = sk * self.G
        return sk, pk

    def cgen(self):
        """
        承诺生成 R ← CGen(1^λ)
        随机数 r ∈ [1, order-1], 承诺 R = r * G
        """
        r = random.randrange(1, self.order)
        R = r * self.G
        return r, R

    def acom(self, R_list):
        """
        承诺聚合 R_A ← ACom({R1, R2, ..., Rn})
        输出: R_A = R1 + R2 + ... + Rn (点加法)
        使用 None 表示单位元（无穷远点）
        """
        R_A = None
        for R in R_list:
            if R_A is None:
                R_A = R
            else:
                R_A = R_A + R
        return R_A

    def psign(self, sk, r, R_A, msg, M):
        """
        部分签名生成 α_i ← PSign(sk, R_A, msg, M)
        输入:
            sk   : 私钥 x
            r    : 承诺阶段的随机数
            R_A  : 聚合承诺（可能为 None）
            msg  : 要签名的消息（可能是默认消息 M 或其他）
            M    : 默认消息
        输出:
            tau  : 部分签名值 τ = r + c_msg * x   (mod order)
            D    : 字典 {msg: [公钥]}  若 msg == M 则为空字典
        """
        c_msg = self._hash_to_scalar(msg, R_A)
        tau = (r + c_msg * sk) % self.order

        if msg == M:
            D = {}
        else:
            pk = sk * self.G
            D = {msg: [pk]}
        return tau, D

    def sign(self, partials):
        """
        签名聚合 α ← Sign({α1, α2, ..., αn})
        输入: partials = [(τ1, D1), (τ2, D2), ...]
        输出: (τ, D) 聚合签名
        """
        tau_sum = 0
        merged_D = {}
        for tau, D in partials:
            tau_sum = (tau_sum + tau) % self.order
            for msg, pk_list in D.items():
                if msg not in merged_D:
                    merged_D[msg] = []
                merged_D[msg].extend(pk_list)

        # 去除每个消息对应的公钥列表中的重复项
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
        """
        聚合公钥 apk ← APk({pk1, pk2, ..., pkn})
        输出: apk = pk1 + pk2 + ... + pkn
        """
        apk = None
        for pk in pk_list:
            if apk is None:
                apk = pk
            else:
                apk = apk + pk
        return apk

    def vrfy(self, apk, alpha, M, R_A, S_perp):
        """
        聚合签名验证 (b, D) ← Vrfy(apk, α, M, R_A, S_perp)
        输入:
            apk    : 聚合公钥（可能为 None）
            alpha  : 聚合签名 (τ, D_dict)
            M      : 默认消息
            R_A    : 聚合承诺（可能为 None）
            S_perp : 未参与签名的公钥列表（点列表）
        输出:
            (True, D_dict)  验证成功，返回异常设备列表
            (False, None)   验证失败
        """
        tau, D_dict = alpha

        # 计算 apk_M = apk - (S_perp中的公钥) - (D_dict中出现的所有公钥)
        # 使用 _neg_point 实现减法：a - b = a + (-b)
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

        # 计算左侧：τ * G
        left = tau * self.G

        # 计算右侧：R_A + c_M * apk_M + Σ (c_msg * sum_of_pk_in_msg)
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

        # 处理 right 为 None 的情况（即右侧和为无穷远点）
        if right is None:
            # 检查 left 是否也是无穷远点（只有当 tau == 0 时才会发生，概率极低）
            zero_point = self.order * self.G  # 阶乘后得到无穷远点
            valid = (left == zero_point)
        else:
            valid = (left == right)

        if valid:
            return True, D_dict
        else:
            return False, None


