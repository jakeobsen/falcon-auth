#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

from os import environ
import jwt

def decode_jwt(token):
    return jwt.decode(token.split(" ")[1], environ["JWT_PUBKEY"], algorithms='RS256')