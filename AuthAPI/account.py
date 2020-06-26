#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

import logging
import falcon
from functions import decode_jwt

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
        cursor = self.mysql.cursor()
        cursor.execute("UPDATE `users` SET password=%s WHERE `uuid`=%s LIMIT 1",
                       (uuid,))
        cursor.close()
        resp.context.result = {
            "title": "Password changed"
        }