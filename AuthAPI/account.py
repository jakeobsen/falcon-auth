#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import logging
import falcon
from functions import decode_jwt
from password import new_hash, hash_verify

class User:
    def __init__(self, mysql_connection):
        self.mysql = mysql_connection

    def on_get(self, req, resp, uuid=None) -> None:
        """ Handle GET request """
        jwt = decode_jwt(req.auth)
        uuid = jwt['user_uuid']

        # If SQL connection is gone, reconnect
        if not self.mysql.is_connected():
            logging.debug("MySQL connection dropped, reconnecting.")
            self.mysql.reconnect(attempts=3, delay=1)

        # SQL Result
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `username`, `uuid`, `name` FROM `users` WHERE `uuid`=%s LIMIT 1",
                       (uuid,))

        for (username, uuid, name) in cursor:
            sql_username = username
            sql_name = name
            sql_uid = uuid
            break
        cursor.close()
        # SQL End

        user_permissions = []
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `permission` FROM `permissions` WHERE `user_uuid`=%s", (sql_uid,))
        for (permission,) in cursor:
            user_permissions.append(permission)
        cursor.close()
        # Validate hash

        resp.context.result = {
            "username": sql_username,
            "realname": sql_name,
            "user_uuid": sql_uid,
            "user_permissions": user_permissions
        }


class ResetPassword:
    def __init__(self, mysql_connection):
        self.mysql = mysql_connection

    def on_post(self, req, resp, uuid=None) -> None:
        jwt = decode_jwt(req.auth)
        try:
            doc = req.context.doc
        except AttributeError as e:
            logging.debug(str(e))
            raise falcon.HTTPBadRequest('JSON Body Missing')

        try:
            old_password = doc["oldpassword"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("oldpassword")

        try:
            new_password = doc["newpassword"]
        except KeyError as e:
            logging.debug(str(e))
            raise falcon.HTTPMissingParam("newpassword")

        if uuid is None:
            uuid = jwt['user_uuid']

        # If SQL connection is gone, reconnect
        if not self.mysql.is_connected():
            logging.debug("MySQL connection dropped, reconnecting.")
            self.mysql.reconnect(attempts=3, delay=1)

        # SQL Result
        cursor = self.mysql.cursor()
        cursor.execute("SELECT `password`, `uuid` FROM `users` WHERE `uuid`=%s LIMIT 1",
                       (uuid,))

        for (password, uuid) in cursor:
            sql_password = password
            sql_uid = uuid
            break
        # SQL End

        new_pass_hash = new_hash(new_password)
        if hash_verify(old_password, sql_password):
            print("hash match")
        else:
            raise falcon.HTTPUnauthorized(
                "Old password is invalid",
                "The old password you entered does not match the one we have on record."
            )

        cursor.execute("UPDATE `users` SET password=%s WHERE `uuid`=%s LIMIT 1", (new_pass_hash, uuid,))
        self.mysql.commit()
        cursor.close()
        self.mysql.reconnect(attempts=3, delay=1)

        resp.context.result = {
            "title": "Password changed"
        }