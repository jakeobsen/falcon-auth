#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import logging
from os import environ

import mysql.connector.pooling
import redis
from falcon import API

from AuthAPI.authentication import ValidateLogin, ValidateJWT
from middleware import RequireJSON, JSONTranslator
from AuthAPI.account import User

# Debug Level
logging.basicConfig(level=logging.DEBUG)

# MariaDB Config
dbconfig = {
    "user": environ['MYSQL_USER'],
    "password": environ['MYSQL_PASSWORD'],
    "host": environ['MYSQL_HOST'],
    "port": environ['MYSQL_PORT'],
    "database": environ['MYSQL_DATABASE']
}
# MariaDB Pool
mysql_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="authpool",
    pool_size=3,
    **dbconfig)

# Redis Ssetup
redis_pool = redis.ConnectionPool(host=environ["REDIS_HOST"], port=environ["REDIS_PORT"], db=environ["REDIS_DB"])

# API Setup
api = API(middleware=[
    RequireJSON(),
    JSONTranslator(),
])

# Auth API - used to validate username and password
api.add_route('/auth', ValidateLogin(mysql_connection=mysql_pool.get_connection()))

# Debug endpoint - validates JWT tokens issues by /auth endpoint
api.add_route('/validate', ValidateJWT())
