#!/usr/bin/env python3

'''
    B. H. A. S. H
    
    Bijective
    Homomorphic
    AntiQuantum
    Secure
    Hash

    Is a post-quantum, open-source, community developed
    hash function, which is based on polynomial matrices
    rings multiplications and general learning with rounding
    problem.

    For now, it only supports passwords of length 9 though.

    Please, don't remove it from this service! It is vital
    for the service security!!!

    usage:
        $ ./bhash.py "secretpass" 104101108108111
        asodnjasndkgjn123123
        $ ./bhash.py "chicken" 104101108108111
        abxcvijoi1o23j1i2asd
'''

import os
import sys
import random
import hashlib
import functools

import numpy as np


SECRET_CONSTANT = 42


@functools.lru_cache()
def secret_matrix(seed):
    random.seed(seed)
    secret = np.array([random.randint(1, (i + 80) * (i + 1) % 256) for i in range(9)])
    secret = np.squeeze(secret)
    secret = secret.reshape(3, 3)
    return secret


def bhash_transform(l1, l2, l3):
    l1 = l1 * l2 + SECRET_CONSTANT * 2
    l3 = l2 * l3 + SECRET_CONSTANT * 2
    l1, l3 = l3, l1
    for i, (c1, c3) in enumerate(zip(l1, l3)):
        l1[i] = c1 % 256
        l3[i] = c3 % 256
        if i % 2 == 0:
            l1[i] = c3 % 256
            l3[i] = c1 % 256
    return l1, l2, l3


def bhash_left(matrix):
    return (matrix.transpose() * np.eye(3)) ** 2


def bhash_right(secret):
    return (seed * np.fliplr(np.eye(3))) ** 2


def bhash(left, right):
    hash_material = hashlib.sha256((left * right).sum().flatten().tobytes()).digest()
    subhash = hash_material
    for i in range(100):
        subhash = hashlib.sha256(subhash).digest()
        subhash = hashlib.md5(subhash).digest()
        subhash = hashlib.sha3_224(subhash).digest()
        subhash = hashlib.blake2b(subhash).digest()
    return subhash.hex()

def to_matrix(string):
    chunk1, chunk2, chunk3 = (np.array([ord(char) for char in string[i * 3:(i + 1) * 3]]) for i in range(3))
    matrix = np.array(bhash_transform(chunk1, chunk2, chunk3))
    matrix = np.array(bhash_transform(*(matrix[:,i] for i in range(3))))
    return matrix


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Not enough arguments!")

    password = sys.argv[1]
    password = password.center(9)
    password = password[:9]
    pmatrix = to_matrix(password)

    try:
        seed = int(sys.argv[2])
    except:
        sys.exit("Seed is not integer!")
    smatrix = secret_matrix(seed)

    result = bhash(bhash_left(pmatrix), bhash_right(smatrix))
    print(result)
