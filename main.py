#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import logging
from os import environ

import mysql.connector.pooling
from falcon import API

from AuthAPI.authentication import ValidateLogin, ValidateJWT
from middleware import RequireJSON, JSONTranslator

dbconfig = {
    "user": environ['MYSQL_USER'],
    "password": environ['MYSQL_PASSWORD'],
    "host": environ['MYSQL_HOST'],
    "port": environ['MYSQL_PORT'],
    "database": environ['MYSQL_DATABASE']
}

logging.basicConfig(level=logging.DEBUG)
mysql_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="authpool",
    pool_size=3,
    **dbconfig)

api = API(middleware=[
    RequireJSON(),
    JSONTranslator(),
])

api.add_route('/auth', ValidateLogin(mysql_pool.get_connection()))
api.add_route('/validate', ValidateJWT())
