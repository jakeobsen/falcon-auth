#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import logging
from os import environ
from time import time

import falcon
import jwt

from password import hash_verify

from functions import decode_jwt

class ValidateLogin:
    def __init__(self, mysql_connection):
        self.mysql = mysql_connection

    def on_get(self, req, resp) -> None:
        """Handles GET requests"""
        resp.context.result = {
            "jwt_content": decode_jwt(req.auth)
        }

    def on_post(self, req, resp) -> None:
        """Handles POST requests"""

        try:
            doc = req.context.doc
        except AttributeError as e:
            logging.debug(str(e))
            raise falcon.HTTPBadRequest('JSON Body Missing')

        try:
            req_username = doc["username"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("username")

        try:
            req_password = doc["password"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("password")

        # If SQL connection is gone, reconnect
        if not self.mysql.is_connected():
            logging.debug("MySQL connection dropped, reconnecting.")
            self.mysql.reconnect(attempts=3, delay=1)

        # SQL Result
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `username`, `password`, `uuid` FROM `users` WHERE `username`=%s LIMIT 1",
                       (req_username,))

        for (username, password, uuid) in cursor:
            sql_username = username
            sql_password = password
            sql_uid = uuid
            break
        else:
            raise falcon.HTTPUnauthorized(
                "Invalid Login",
                "Wrong username or password"
            )
        cursor.close()
        # SQL End

        user_permissions = []
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `permission` FROM `permissions` WHERE `user_uuid`=%s", (sql_uid,))
        for (permission,) in cursor:
            user_permissions.append(permission)
        cursor.close()
        # Validate hash
        if hash_verify(req_password, sql_password):

            # Todo: add session info to redis cache

            # Return JWT
            resp.context.result = {
                "token": jwt.encode({
                    "iat": int(time()),
                    "nbf": int(time()),
                    "exp": int(time()) + 3600 * 24 * 365, # One year validity as part of early dev stage while testing
                    "username": sql_username,
                    "user_uuid": sql_uid,
                    "user_permissions": user_permissions
                }, environ["JWT_PRIVKEY"], algorithm='RS256').decode()
            }
        else:
            raise falcon.HTTPUnauthorized(
                "Invalid Login",
                "Wrong username or password"
            )
