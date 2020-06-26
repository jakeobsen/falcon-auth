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

from AuthAPI.authentication import ValidateLogin
from middleware import RequireJSON, JSONTranslator, AuthMiddleware
from AuthAPI.account import User, ResetPassword

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
    pool_size=10,
    **dbconfig)

# Redis Setup
redis_pool = redis.ConnectionPool(host=environ["REDIS_HOST"], port=environ["REDIS_PORT"], db=environ["REDIS_DB"])

# API Setup
api = API(middleware=[
    AuthMiddleware(),
    RequireJSON(),
    JSONTranslator(),
])

# Auth API - used to validate username and password
api.add_route('/auth', ValidateLogin(mysql_connection=mysql_pool.get_connection()))

# Debug endpoint - validates JWT tokens issues by /auth endpoint
api.add_route('/user', User(mysql_connection=mysql_pool.get_connection()))
api.add_route('/user/{uuid}', User(mysql_connection=mysql_pool.get_connection()))

api.add_route('/user/resetpassword', ResetPassword(mysql_connection=mysql_pool.get_connection()))
api.add_route('/user/resetpassword/{uuid}', ResetPassword(mysql_connection=mysql_pool.get_connection()))