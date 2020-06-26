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
from password import new_hash, hash_verify

import falcon
import jwt


class ValidateLogin:
    def __init__(self, mysql_connection):
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
                "iat": int(time()),
                "nbf": int(time()),
                "exp": int(time()) + 3600
            }, environ["JWT_PRIVKEY"], algorithm='RS256').decode()
        }

    def on_get(self, req, resp) -> None:
        """Handles GET requests"""
        raise falcon.HTTPBadRequest("This endpoint only support POST requests.")

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

        # SQL Result
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `username`, `password`, `uuid`, `name` FROM `users` "
                       "WHERE `username`=%s LIMIT 1", (req_username,))

        for (username, password, uuid, name) in cursor:
            sql_username = username
            sql_password = password
            sql_name = name
            sql_uid = uuid
            break
        else:
            raise falcon.HTTPUnauthorized(
                "Invalid Login",
                "Wrong username or password"
            )
        cursor.close()
        # SQL End

        if hash_verify(req_password, sql_password):
            resp.context.result = self.result(
                username=sql_username,
                name=sql_name,
                uuid=sql_uid,
            )
        else:
            raise falcon.HTTPUnauthorized(
                "Invalid Login",
                "Wrong username or password"
            )

# This is a debug class for now - it validates an issued JWT
# and returns it's content if it's valid otherwise an error
class ValidateJWT:
    # noinspection PyMethodMayBeStatic
    def on_post(self, req, resp) -> None:
        """Handles POST requests"""

        try:
            doc = req.context.doc
        except AttributeError:
            raise falcon.HTTPBadRequest('JSON Body Missing')

        try:
            data = jwt.decode(doc['jwt'], environ["JWT_PUBKEY"], algorithms='RS256')
        except Exception as e:
            logging.debug(str(e))
            raise falcon.HTTPUnauthorized(str(e))

        now = int(time())
        if data['nbf'] > now:
            logging.debug("Tried to auth a JWT from the future")
            raise falcon.HTTPUnauthorized(
                "Authorisation Token Invalid",
                "The supplied token has been issued in the future. It is invalid."
            )

        resp.context.result = {
            "jwt_content": data
        }
