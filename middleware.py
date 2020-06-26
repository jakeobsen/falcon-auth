#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

# Default falcon middleware

import json
from os import environ
import jwt
from time import time

import falcon


class RequireJSON(object):

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable('This API only supports responses encoded as JSON.')

        if req.method in ('POST', 'PUT'):
            if req.content_type is None or 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType('This API only supports requests encoded as JSON.')


class JSONTranslator(object):
    # NOTE: Starting with Falcon 1.3, you can simply
    # use req.media and resp.media for this instead.

    def process_request(self, req, resp):
        # req.stream corresponds to the WSGI wsgi.input environ variable,
        # and allows you to read bytes from the request body.
        #
        # See also: PEP 3333
        if req.content_length in (None, 0):
            # Nothing to do
            return

        body = req.stream.read()
        if not body:
            raise falcon.HTTPBadRequest('Empty request body', 'A valid JSON document is required.')

        try:
            req.context.doc = json.loads(body.decode('utf-8'))

        except (ValueError, UnicodeDecodeError):
            raise falcon.HTTPError(falcon.HTTP_753,
                                   'Malformed JSON',
                                   'Could not decode the request body. The '
                                   'JSON was incorrect or not encoded as '
                                   'UTF-8.')

    def process_response(self, req, resp, resource, x):
        if not hasattr(resp.context, 'result'):
            return
        resp.body = json.dumps(resp.context.result)


class AuthMiddleware(object):

    def process_request(self, req, resp):
        token = req.get_header('Authorization')

        if req.relative_uri == "/auth" and req.method == "POST":
            pass
        else:
            if token is None:
                raise falcon.HTTPUnauthorized('Auth token required',
                                              'Please provide an auth token '
                                              'as part of the request.')

            if not self._token_is_valid(token):
                raise falcon.HTTPUnauthorized('Authentication required',
                                              'The provided auth token is not valid. '
                                              'Please request a new token and try again.')

    def _token_is_valid(self, token):
        """Handles GET requests"""
        doc = token.split(" ")[1]
        data = {}

        try:
            data = jwt.decode(doc, environ["JWT_PUBKEY"], algorithms='RS256')
            token_validity = True
        except Exception:
            token_validity = False

        if 'nbf' in data and data['nbf'] > int(time()):
            token_validity = False

        return token_validity

        # if req.content_type == "application/json":
        #     if req.content_length:
        #         try:
        #             doc = json.load(req.stream)
        #         except json.decoder.JSONDecodeError as e:
        #             error = str(e)
        #             response_code = falcon.HTTP_400
        #         except Exception as e:
        #             logging.debug(str(e))
        #             error = "Internal server error."
        #             response_code = falcon.HTTP_500
        #     else:
        #         error = "No request body supplied. Expected json type object."
        #         response_code = falcon.HTTP_400
        # else:
        #     error = "Wrong content type. Expected application/json type."
        #     response_code = falcon.HTTP_400
