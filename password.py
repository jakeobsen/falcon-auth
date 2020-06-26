#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

from hashlib import scrypt
from os import urandom

def hash_gen(text, salt):
    return scrypt(
        password=text.encode(),
        salt=salt.encode(),
        n=1024,
        r=8,
        p=100,
        dklen=64
    ).hex()

def new_hash(text):
    salt = urandom(32).hex()
    hash = hash_gen(text, salt)
    padding = urandom(160).hex()
    return f"{hash}{salt}{padding}"

def hash_split(orig_hash):
    hash = orig_hash[:128]
    salt = orig_hash[128:((len(orig_hash)-len(hash)-64)*-1)]
    return (hash, salt)

def hash_verify(text, orig_hash):
    hash, salt = hash_split(orig_hash)
    comp_hash = hash_gen(text, salt)


    return hash == comp_hash


if __name__ == "__main__":
    text = "password"
    myhash = new_hash(text)
    if hash_verify(text, myhash):
        print("OK")
