#!/usr/bin/python3

import hmac
import hashlib
import math
import json
import numpy.random
from bitarray import bitarray
from bitarray import util as bitutil
from queue import Queue, LifoQueue
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.crypto.cryptobase import MODE_ECB
from charm.core.math.integer import randomBits, serialize, integer


def gen_key2(keylength):
    return serialize(integer(randomBits(keylength)))


def gen_key(keylength):
    assert keylength % 8 == 0
    temp_key = randomBits(keylength)
    return temp_key.to_bytes(int(keylength / 8), byteorder="big")


def prf_256(key, data):
    if not isinstance(data, bytes):
        data = bytes(data, "utf-8")
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()  # output's length is 32, i.e., 32 * 8 = 256


def prf_512(key, data):
    if not isinstance(data, bytes):
        data = bytes(data, "utf-8")
    h = hmac.new(key, data, hashlib.sha512)
    return h.digest()  # output's length is 64, i.e., 64 * 8 = 512


def prf_p(key, data, group):
    # h = prf_512(key, data)
    # print(h)
    return group.hash(integer(key), integer(data))


def aes_enc(key, plaintext):
    symcrypt = SymmetricCryptoAbstraction(key)
    return symcrypt.encrypt(plaintext)


def aes_dec(key, cryptext):
    symcrypt = SymmetricCryptoAbstraction(key)
    return symcrypt.decrypt(cryptext)


def aes_enc_dte(key, plaintext):
    symcrypt = SymmetricCryptoAbstraction(key, mode=MODE_ECB)
    cryptext = symcrypt.encrypt(plaintext)
    return json.loads(cryptext)["CipherText"]


def aes_dec_dte(key, cryptext):
    symcrypt = SymmetricCryptoAbstraction(key, mode=MODE_ECB)
    format_cryptext = {
        "ALG": 0,
        "MODE": 1,
        "IV": "NS/42lvkurE0spw6c113yB==",
        "CipherText": cryptext}
    plaintext = symcrypt.decrypt(json.dumps(format_cryptext))
    return plaintext


def geometric(epsilon=0.5, delta=10 ** (-6)):
    r = math.exp(-epsilon)
    # n = math.ceil(-1 / epsilon * math.log((delta * (1 + r)) / (1 - r + 2 * r * delta)))
    n = math.ceil(-1 / epsilon * math.log((delta * (1 + r)) / (1 - r ** 2 + 2 * r * delta)))  # ensure Delta=2
    A = (1 - r) / (1 + r - 2 * (r ** (n + 1)))
    # n = 25
    sample_list = list(range(1, 2 * n + 1))
    pr = [A * (r ** abs(n - x)) for x in sample_list]
    pr[n] += 1 - sum(pr)  # make sure the sum(pr) is equal to 1
    return numpy.random.choice(sample_list, p=pr)


def geometric2(epsilon=0.5, n=50):
    r = math.exp(-epsilon)
    A = (1 - r) / (1 + r - 2 * (r ** (n + 1)))
    # delta = A * (r ** n)
    sample_list = list(range(1, 2 * n + 1))
    pr = [A * (r ** abs(n - x)) for x in sample_list]
    pr[n] += 1 - sum(pr)  # make sure the sum(pr) is equal to 1
    return numpy.random.choice(sample_list, p=pr)


def hash_to_fixsize(bytesize, content):
    # constrain the output's size (as =bytesize)
    if bytesize > 64:
        for_count = math.ceil(bytesize / 64)
        result_list = []
        last_length = bytesize
        for i in range(for_count):
            if i == for_count - 1:
                result_list.append(hash_to_fixsize(last_length, content))
            else:
                result_list.append(hash_to_fixsize(64, content))
                last_length -= 64
        return b"".join(result_list)
    hash_obj = hashlib.blake2b(digest_size=bytesize)
    hash_obj.update(content)
    return hash_obj.digest()


def bxor(b1, b2):
    if b1 == 0:
        return b2
    assert len(b1) == len(b2)
    return bytes(x ^ y for x, y in zip(b1, b2))


def bxor2(b1, b2):
    if b1 == 0:
        return b2
    assert len(b1) == len(b2)
    return b1 ^ b2


def bip(b1, b2):
    # compute inner product
    assert isinstance(b1, bitarray)
    assert isinstance(b2, list)
    assert len(b1) == len(b2)
    result = 0
    for i, b in enumerate(b1):
        if b == 1 and b2[i] != 0:
            result = bxor(result, b2[i])
    return result


def shve_query(s, c):
    (d_0, d_1, S) = s
    K_prime = 0
    for i in S:
        K_prime = bxor(K_prime, c[i])
    K_prime = bxor(d_0, K_prime)
    mu_prime = aes_dec(K_prime, d_1)
    if mu_prime == b"0":
        return 1
    else:
        return 0


def calcu_bf_pos(element, t, m):
    pos_list = []
    for ct in range(t):
        pos_b = hash_to_fixsize(64, element + str(ct).encode())
        pos_convert = int.from_bytes(pos_b, byteorder="big") % m
        pos_list.append(pos_convert)
    return pos_list


class RBOKVS(object):
    """docstring for OKVS
    :n: rows
    :m: columns
    :w: length of band
    The choice of parameters:
    m = (1 + epsilon)n
    w = O(lambda / epsilon + log n)
    For example:
    m = 2^10, epsilon = 0.1,
    ==> n = (1+0.1) * 2^10
    ==> w = (lambda + 19.830) / 0.2751
    """

    def __init__(self, M, N, W):
        assert W % 8 == 0
        self.M = M
        self.N = N
        self.W = W

    def __hash1__(self, key):
        """
        hash a key to a specific position
        h_1(key) -> [0, M - W]
        """
        hash_range = self.M - self.W
        # pos_b = hash_to_fixsize(64, key.encode())
        pos_bin = hash_to_fixsize(64, key)
        pos_convert = int.from_bytes(pos_bin, byteorder="big") % hash_range
        return pos_convert

    def __hash2__(self, key):
        # hash_bytes = hash_to_fixsize(self.W / 8, key.encode())
        hash_bytes = hash_to_fixsize(int(self.W / 8), key)
        band = bitarray()
        band.frombytes(hash_bytes)
        # band = bytearray(hash_bytes)
        # band = bin(int.from_bytes(hash_bytes, byteorder="big"))[2:]
        return band

    def calcu_coding(self, key):
        start_pos = self.__hash1__(key)
        band = self.__hash2__(key)
        rest_pos = self.M - self.W - start_pos
        result = bitutil.zeros(start_pos) + band + bitutil.zeros(rest_pos)
        return (start_pos, result)

    def encode(self, kv_store):
        """
        :kv_store: dict
        """
        assert len(kv_store) == self.N
        pos_dic = {}  # 记录每一个 key 映射的起始位置
        key_encode = {}  # 记录每一个 key 映射的向量
        for k in kv_store.keys():
            start_pos, trans_conding = self.calcu_coding(k)
            pos_dic.setdefault(k, start_pos)
            key_encode.setdefault(k, trans_conding)

        sorted_pos = dict(sorted(pos_dic.items(), key=lambda item: item[1]))
        start_list = [x for x in sorted_pos.values()]
        b = [kv_store.get(k) for k in sorted_pos.keys()]
        sorted_coding = [key_encode.get(k) for k in sorted_pos.keys()]

        piv = [0] * self.N
        for i in range(self.N):
            for j in range(start_list[i], start_list[i] + self.W):
                if sorted_coding[i][j] == 1:
                    piv[i] = j
                    for i_p in range(i + 1, self.N):
                        if start_list[i_p] <= piv[i]:
                            if sorted_coding[i_p][piv[i]] == 1:
                                sorted_coding[i_p] ^= sorted_coding[i]
                                b[i_p] = bxor(b[i_p], b[i])
                    break
            if piv[i] == 0:
                raise RuntimeError(f"Fail to initialize at {i}th row!")
        z = [0] * self.M
        for i in range(self.N - 1, -1, -1):
            z[piv[i]] = bxor(bip(sorted_coding[i], z), b[i])
        # return (sorted_coding, original_coding)
        # self.z = z
        return z

    def decode(self, k, z):
        _, trans_conding = self.calcu_coding(k)
        return bip(trans_conding, z)


class SHVE(object):
    """docstring for SHVE"""

    def __init__(self, kappa, MSK=0):
        assert kappa == 512
        #  512 / 8 = 64，the len(kappa) is 64
        self.kappa = kappa
        if MSK != 0:
            self.MSK = MSK
        else:
            self.MSK = gen_key(kappa)
        self.Message = "True"

    def key_gen(self, v):
        """
        Output:
        (d_0, d_1)
        """
        S = []
        for i, j in enumerate(v):
            if j != "*":
                S.append(i)
        d_0 = int(0).to_bytes(int(self.kappa / 8), byteorder="big")
        for i in S:
            d_0 = bxor(d_0, prf_512(self.MSK, str(v[i]) + str(i)))
        K = gen_key(self.kappa)
        d_0 = bxor(d_0, K)
        d_1 = aes_enc(K, "0")
        return (d_0, d_1, S)

    def enc(self, x):
        c = []
        for i, j in enumerate(x):
            c.append(prf_512(self.MSK, str(j) + str(i)))
        return c

    def query(self, s, c):
        (d_0, d_1, S) = s
        K_prime = int(0).to_bytes(int(self.kappa / 8), byteorder="big")
        for i in S:
            K_prime = bxor(K_prime, c[i])
        K_prime = bxor(d_0, K_prime)
        mu_prime = aes_dec(K_prime, d_1)
        if mu_prime == b"0":
            return 1
        else:
            return 0


class BloomFilter(object):
    """docstring for BloomFilter"""

    def __init__(self, n, error_rate):
        # :n: the number of elements
        self.m = int(-1 * (n * math.log(error_rate)) / (math.log(2) ** 2))
        # :m: the length of Bloom filter
        self.t = int((self.m / n) * math.log(2))
        # :t: the number of hash functions
        self.B = ["0" for i in range(self.m)]

    def gen_filter(self, S):
        for item in S:
            for ct in range(self.t):
                pos_b = hash_to_fixsize(64, item + str(ct).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.m
                self.B[pos_convert] = "1"
        return self.B

    def calcu_pos(self, element):
        pos_list = []
        for ct in range(self.t):
            pos_b = hash_to_fixsize(64, element + str(ct).encode())
            pos_convert = int.from_bytes(pos_b, byteorder="big") % self.m
            pos_list.append(pos_convert)
        return pos_list

    def test(self, element):
        for ct in range(self.t):
            pos_b = hash_to_fixsize(64, element + str(ct).encode())
            pos_convert = int.from_bytes(pos_b, byteorder="big") % self.m
            if self.B[pos_convert] == "0":
                return False
        return True


class XORFilter(object):
    """docstring for XORFilter"""

    def __init__(self, s):
        self.HASH_COUNT = 3
        self.s = s
        self.B = [[] for x in range(self.s)]

    def mapping(self, S):
        self.T = [[] for x in range(self.s)]
        T_Queue = Queue()
        T_Stack = LifoQueue()
        for x in S:
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                # pos_convert = round(pos_b / 65535 * (self.s - 1))
                self.T[pos_convert].append(x)

        for i in range(self.s):
            if len(self.T[i]) == 1:
                T_Queue.put(i)

        while T_Queue.qsize() != 0:
            i = T_Queue.get()
            if self.T[i] == []:
                continue
            x = self.T[i][0]

            T_Stack.put((x, i))
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                # pos_convert = round(pos_b / 65535 * (self.s - 1))
                self.T[pos_convert].remove(x)
                if self.T[pos_convert] == 1:
                    T_Queue.put(pos_convert)

        # if len(T_Stack) != len(S)
        # assert T_Stack.qsize() == len(S)
        return T_Stack

    def gen_filter(self, kv_store, group):
        """
        :kv_store: dic
        """
        B = [0 for i in range(self.s)]
        T_Stack = self.mapping(list(kv_store.keys()))
        while T_Stack.qsize() != 0:
            (x, i) = T_Stack.get()
            B[i] = kv_store[x]
            # B.setdefault(i, kv_store[x])
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                if pos_convert != i:
                    if B[pos_convert] == 0:
                        B[pos_convert] == group.random()
                    B[i] = bxor(B[pos_convert], B[i])
        self.B = B
        # return B

    def test(self, element, fingerprinter):
        fp = 0
        for t in range(self.HASH_COUNT):
            pos_b = hash_to_fixsize(64, element + str(t).encode())
            pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
            fp = bxor(fp, self.B[pos_convert])
        if fp == fingerprinter:
            return True
        else:
            return False


class OKVS(object):
    """docstring for XORFilter"""

    def __init__(self, s):
        self.HASH_COUNT = 3
        self.s = s
        self.B = [[] for x in range(self.s)]

    def mapping(self, S):
        self.T = [[] for x in range(self.s)]
        T_Queue = Queue()
        T_Stack = LifoQueue()
        for x in S:
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                # pos_convert = round(pos_b / 65535 * (self.s - 1))
                self.T[pos_convert].append(x)

        for i in range(self.s):
            if len(self.T[i]) == 1:
                T_Queue.put(i)

        while T_Queue.qsize() != 0:
            i = T_Queue.get()
            if self.T[i] == []:
                continue
            x = self.T[i][0]

            T_Stack.put((x, i))
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                # pos_convert = round(pos_b / 65535 * (self.s - 1))
                self.T[pos_convert].remove(x)
                if self.T[pos_convert] == 1:
                    T_Queue.put(pos_convert)

        # if len(T_Stack) != len(S)
        # assert T_Stack.qsize() == len(S)
        return T_Stack

    def gen_store(self, kv_store, group):
        """
        :kv_store: dic
        """
        B = {}
        T_Stack = self.mapping(list(kv_store.keys()))
        while T_Stack.qsize() != 0:
            (x, i) = T_Stack.get()
            B.setdefault(i, kv_store[x])
            hash_length = len(kv_store[x])
            for t in range(self.HASH_COUNT):
                pos_b = hash_to_fixsize(64, x + str(t).encode())
                pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
                if pos_convert != i:
                    if B.get(pos_convert) is None:
                        random_seed = group.serialize(group.random())
                        # random_tag = hash_to_fixsize(8, random_seed)
                        random_tag = hash_to_fixsize(hash_length, random_seed)
                        # e 的长度为 117
                        B.setdefault(pos_convert, random_tag)
                    B[i] = bxor(B[pos_convert], B[i])
        self.B = B
        # return B

    def calcu_pos(self, element):
        pos_list = []
        for t in range(self.HASH_COUNT):
            pos_b = hash_to_fixsize(64, element + str(t).encode())
            pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
            pos_list.append(pos_convert)
        assert len(pos_list) == len(set(pos_list))
        return pos_list

    def test(self, element, fingerprinter):
        fp = 0
        for t in range(self.HASH_COUNT):
            pos_b = hash_to_fixsize(64, element + str(t).encode())
            pos_convert = int.from_bytes(pos_b, byteorder="big") % self.s
            fp = bxor(fp, self.B[pos_convert])
        if fp == fingerprinter:
            return True
        else:
            return False


if __name__ == '__main__':
    shve_op = SHVE(512)
    v = [0, 1, 1, "*", 0]
    x = [0, 1, 1, 1, 0]
    s = shve_op.key_gen(v)
    c = shve_op.enc(x)
    print(shve_op.query(s, c))
