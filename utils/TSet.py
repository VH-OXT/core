#!/usr/bin/python3

import random
import time
from .crypto_tools import prf_512, hash_to_fixsize, bxor


class TSet(object):
    """
    init for TSet, e.g., TSetSetup(T)
    B, the length of TSet
    S, the lenght of each element in TSet
    K_T, the secret key for TSet
    """

    def __init__(self):
        # self.B = B
        # self.S = S
        self.B = 256
        # self.k_t = k_t

    def __count_S__(self, T, k_t):
        pos_record = {}
        for keyword in T.keys():
            stag = prf_512(k_t, keyword)
            # print(type(stag))
            for i, j in enumerate(T.get(keyword)):
                # self.B = 256 (2 ** 8)
                assert self.B == 256
                pos_b = hash_to_fixsize(1, stag + str(i).encode())
                counter = pos_record.setdefault(pos_b, 0)
                counter += 1
                pos_record[pos_b] = counter
        return max([pos_record[x] for x in pos_record])

    def setup(self, T, k_t):
        # 根据 B 计算出 S 的安全取值
        start = time.process_time()
        self.S = self.__count_S__(T, k_t)
        end = time.process_time()
        print(end - start)
        free_list = [list(range(self.S)) for i in range(self.B)]
        self.TSet = [[(0, 0) for j in range(self.S)] for i in range(self.B)]

        # 生成 stag，并将每个 (keyword, (e, y)) 存储到哈希表中
        for keyword in T.keys():
            stag = prf_512(k_t, keyword)
            t = T.get(keyword)  # t is the array of (e,y)
            for i, j in enumerate(t):
                # j -> (e, y), len(e)
                (e, y) = j
                assert len(e) == 117  # 确保 AES 加密后密文长度为 117
                concat_ey = e.encode() + y
                """
                计算哈希表位置
                i.e., hash(F(stag, i)) -> (b, L, K)
                b, the position to store (keyword, id) in TSet
                L, the label for (keyword, id)
                K, used to encrypt the value of (keyword, id)
                pseudocode
                (b, L, K) = H(F(stag, i))
                """
                b = int.from_bytes(hash_to_fixsize(1, stag + str(i).encode()), byteorder="big")
                # L = hash_to_fixsize(256, (keyword + str(i)).encode())
                L = hash_to_fixsize(256, stag + str(i).encode())
                K = hash_to_fixsize(len(concat_ey) + 1, stag + str(i).encode())
                # b_pos = free_list[b].pop(random.choice(len(free_list[b] - 1)))
                # b_pos = free_list[b].pop(random.choice(free_list[b]))
                b_pos = random.choice(free_list[b])
                free_list[b].remove(b_pos)
                beta = b"1"
                if i == len(t) - 1:
                    beta = b"0"
                c = bxor(K, beta + concat_ey)
                self.TSet[b][b_pos] = (L, c)

    def retrive(self, stag):
        # 根据stag取相应的结果
        beta = "1"
        counter = 0
        t_res = []
        while beta == "1":
            K = None
            b = int.from_bytes(hash_to_fixsize(1, stag + str(counter).encode()), byteorder="big")
            L = hash_to_fixsize(256, stag + str(counter).encode())
            for (label, value) in self.TSet[b]:
                if label == L:
                    if not K:
                        K = hash_to_fixsize(len(value), stag + str(counter).encode())
                    temp = bxor(K, value)
                    beta = temp[0:1].decode()
                    t_res.append(temp)
                    # if beta == "0":
                    # return t_res
            counter += 1
        return t_res


class TSet2(TSet):
    """docstring for TSet2"""

    def setup(self, T, k_t):
        # 根据 B 计算出 S 的安全取值
        start = time.process_time()
        self.S = self.__count_S__(T, k_t)
        end = time.process_time()
        print(end - start)
        free_list = [list(range(self.S)) for i in range(self.B)]
        self.TSet = [[(0, 0) for j in range(self.S)] for i in range(self.B)]

        # 生成 stag，并将每个 (keyword, (e, y)) 存储到哈希表中
        for keyword in T.keys():
            stag = prf_512(k_t, keyword)
            t = T.get(keyword)  # t is the array of (e,y)
            for i, j in enumerate(t):
                # j -> (e, y), len(e)
                y = j
                # assert len(e) == 117  # 确保 AES 加密后密文长度为 117
                # concat_ey = e.encode() + y
                stag_p = stag + str(i).encode()
                b = int.from_bytes(hash_to_fixsize(1, stag_p), byteorder="big")
                L = hash_to_fixsize(256, stag + str(i).encode())
                K = hash_to_fixsize(len(y) + 1, stag + str(i).encode())
                b_pos = random.choice(free_list[b])
                free_list[b].remove(b_pos)
                beta = b"1"
                if i == len(t) - 1:
                    beta = b"0"
                c = bxor(K, beta + y)
                self.TSet[b][b_pos] = (L, c)
