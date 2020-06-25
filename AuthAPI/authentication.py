#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import hashlib
import json
import logging
from os import environ
from time import time

import falcon
import jwt
import redis


class ValidateLogin:
    def __init__(self, mysql_connection):
        self.redis = redis.Redis(host='localhost', port=6379, db=0)
        self.mysql = mysql_connection

    @staticmethod
    def result(username, name, uuid) -> dict:
        """
        Encode params to jwt and return dict

        :param username: username string
        :param name: real name string
        :param uuid: uuid4 string
        :return: returns a dict ready to send to resp.context.result
        """
        return {
            "jwt": jwt.encode({
                "username": username,
                "name": name,
                "uid": uuid,
                "iat": int(time())
            }, environ["JWT_PRIVKEY"], algorithm='RS256').decode()
        }

    def on_post(self, req, resp):
        """Handles POST requests"""

        try:
            doc = req.context.doc
        except AttributeError as e:
            logging.debug(str(e))
            raise falcon.HTTPBadRequest('JSON Body Missing')

        try:
            username = doc["username"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("username")

        try:
            password = doc["password"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("password")

        # Cache lookup
        username_hash = hashlib.sha256(username.encode()).hexdigest()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cache_data = self.redis.get(f"login_cache_{username_hash}")

        # If a cached result exists in redis, then use that for authentication
        # otherwise lookup in SQL database

        if cache_data:
            # Cached result
            cache = json.loads(cache_data)
            if all(key in cache for key in ("username", "password", "name", "uuid")):
                if cache['username'] == username and cache['password'] == password_hash:
                    resp.context.result = self.result(
                        username=cache['username'],
                        name=cache['name'],
                        uuid=cache['uuid'],
                    )
                else:
                    raise falcon.HTTPUnauthorized(
                        "Invalid Login",
                        "Wrong username or password"
                    )
        else:
            # SQL Result
            cursor = self.mysql.cursor()
            cursor.execute("SELECT `username`, `password`, `uuid`, `name` FROM `users` "
                           "WHERE `username`=%s and `password`=%s LIMIT 1", (username, password_hash))

            for (username, password, uuid, name) in cursor:
                sql_username = username
                sql_name = name
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

            # Update cache
            self.redis.set(f"login_cache_{username_hash}", json.dumps({
                "username": sql_username,
                "name": sql_name,
                "uuid": sql_uid,
                "password": sql_password
            }))
            self.redis.expire(f"login_cache_{username_hash}", 3600)

            # Response
            resp.context.result = self.result(
                username=sql_username,
                name=sql_name,
                uuid=sql_uid,
            )


# This is a debug class for now - it validates an issued JWT
# and returns it's content if it's valid otherwise an error
class ValidateJWT:
    # noinspection PyMethodMayBeStatic
    def on_post(self, req, resp):
        """Handles POST requests"""

        try:
            doc = req.context.doc
        except AttributeError:
            raise falcon.HTTPBadRequest('JSON Body Missing')

        try:
            data = jwt.decode(doc['jwt'], environ["JWT_PUBKEY"], algorithms='RS256')
        except Exception as e:
            raise falcon.HTTPBadRequest(str(e))

        resp.context.result = {
            "jwt_content": data
        }
