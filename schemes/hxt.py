#!/usr/bin/python3

import os
import random
from charm.toolbox.integergroup import IntegerGroupQ
from utils import crypto_tools, TSet


class Client(object):
    def __init__(self, kappa=512):
        random_K = [crypto_tools.gen_key(512) for i in range(5)]
        (self.k_s, self.k_t, self.k_x, self.k_i, self.k_z) = random_K
        self.group = IntegerGroupQ()
        self.group.paramgen(kappa)
        self.g = self.group.randomGen()
        self.TSet = TSet.TSet()

    def setup(self, db):
        T = {}
        XSet = set()
        for keyword in db.invert_index.keys():
            t = []
            k_e = crypto_tools.prf_256(self.k_s, keyword)
            file_list = db.invert_index.get(keyword)
            random_seed = random.SystemRandom(os.urandom(4))
            random.SystemRandom.shuffle(random_seed, file_list)
            c = 0
            xkw = crypto_tools.prf_p(self.k_x, keyword, self.group)
            for file in file_list:
                xind = crypto_tools.prf_p(self.k_i, file, self.group)
                z = crypto_tools.prf_p(self.k_z, keyword + str(c), self.group)
                y = self.group.serialize(xind * (z ** -1))  # type: bytes
                e = crypto_tools.aes_enc(k_e, file)
                t.append((e, y))
                xtag = self.group.serialize(self.g ** (xkw * xind))
                XSet.add(xtag)
                c += 1
            T.setdefault(keyword, t)
        self.TSet.setup(T, self.k_t)
        BF = crypto_tools.BloomFilter(len(XSet), 0.0001)
        BF.gen_filter(XSet)
        SHVE = crypto_tools.SHVE(512)
        c = SHVE.enc(BF.B)
        self.XSet = XSet
        self.c = c
        self.BF = BF
        self.SHVE = SHVE

    def init_local(self, keylist, BF, MSK, c, group_para, g):
        (self.k_s, self.k_t, self.k_x, self.k_i, self.k_z) = keylist
        self.BF = BF
        self.SHVE = crypto_tools.SHVE(512, MSK)
        self.c = c
        self.group = IntegerGroupQ()
        self.group.setparam(group_para.p, group_para.para.q)
        self.g = self.group.deserialize(g)

    def gen_stag(self, kwlist):
        w_1 = kwlist[0]
        stag = crypto_tools.prf_512(self.k_t, w_1)
        return stag

    def gen_tokens(self, kwlist, s_length):
        w_1 = kwlist[0]
        xtokens = [[] for x in range(s_length)]
        for c in range(s_length):
            for keyword in kwlist[1:]:
                z = crypto_tools.prf_p(self.k_z, w_1 + str(c), self.group)
                xkw = crypto_tools.prf_p(self.k_x, keyword, self.group)
                xtokens[c].append(self.g ** (z * xkw))
        return xtokens

    def gen_vec(self, u_pos):
        v_c = []
        for t in range(len(u_pos)):
            temp_list = ["*" for i in range(self.BF.m)]
            for i in range(self.BF.m):
                if i in u_pos[t]:
                    temp_list[i] = "1"
            v_c.append(temp_list)
        token_c = []
        for v in v_c:
            token_c.append(self.SHVE.key_gen(v))
        return token_c

    def res_dec(self, w_1, results):
        plain_text = []
        k_e = crypto_tools.prf_256(self.k_s, w_1)
        for enc_text in results:
            plain_text.append(crypto_tools.aes_dec(k_e, enc_text))
        return plain_text


class Server(object):
    """docstring for Server"""

    def __init__(self, TSet, c, BF_para, group):
        self.TSet = TSet
        self.c = c
        (self.t, self.m) = BF_para
        self.group = group

    def search_1(self, stag):
        t_res = self.TSet.retrive(stag)
        self.t_res = t_res
        return len(t_res)

    def search_2(self, xtokens):
        assert len(self.t_res) == len(xtokens)
        u_pos = [[] for i in range(len(self.t_res))]
        enc_candidate = []
        for count, item in enumerate(self.t_res):
            (e, y) = (item[1:118], item[118:])
            enc_candidate.append(e)
            y = self.group.deserialize(y)
            for token in xtokens[count]:
                xtag = self.group.serialize(token ** y)
                u_pos[count] = crypto_tools.calcu_bf_pos(xtag, self.t, self.m)
        self.enc_candidate = enc_candidate
        return u_pos

    def search_3(self, token_c):
        enc_results = []
        for tc, res in zip(token_c, self.enc_candidate):
            if crypto_tools.shve_query(tc, self.c):
                enc_results.append(res.decode())
        return enc_results

    def search(self, stag, xtokens):
        t = self.TSet.retrive(stag)
        assert len(t) == len(xtokens)
        enc_result = []
        for count, item in enumerate(t):
            # assert len(e) == 117
            (e, y) = (item[1:118], item[118:])
            y = self.group.deserialize(y)
            for token in xtokens[count]:
                if self.group.serialize(token ** y) in self.XSet:
                    enc_result.append(e.decode())
        return enc_result


if __name__ == '__main__':
    pass
