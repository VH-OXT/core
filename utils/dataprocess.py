#!/usr/bin/python3

import os
import nltk


class DB(object):
    """
    根据给定的数据集目录，构建对应的正排索引和倒排索引，方便后续构建 TSet 和 XSet
    """

    def __init__(self):
        self.invert_index = {}  # 倒排索引，字典类型，按照关键词检出文件 id
        self.forward_index = []  # 正排索引，由 (filepath, keywords) 元组构成
        self.file_list = []
        self.keywords = set()

    def constructDB(self, folder_name):
        self.file_list = []
        for file_name in os.listdir(folder_name):
            self.file_list.append(os.path.join(folder_name, file_name))
        for file_path in self.file_list:
            words = set()
            with open(file_path, "r") as f:
                for line in f:
                    sentences = nltk.sent_tokenize(line)
                    for sentence in sentences:
                        words = words.union(nltk.word_tokenize(sentence))
            self.forward_index.append((file_path, words))
            self.keywords = self.keywords.union(words)
            for word in words:
                if self.invert_index.setdefault(word, []) is not []:
                    self.invert_index[word].append(file_path)


if __name__ == '__main__':
    localdb = DB()
    localdb.constructDB("../dataset/test")
    print(localdb.invert_index)
