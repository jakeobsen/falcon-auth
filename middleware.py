#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Morten Jakobsen - All rights reserved.
# This software is licensed under the BSD 2-Clause License
# Please see LICENSE for more information.

# Default falcon middleware

import json

import falcon


class RequireJSON(object):

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'This API only supports responses encoded as JSON.',
                href='http://docs.examples.com/api/json')

        if req.method in ('POST', 'PUT'):
            if 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports requests encoded as JSON.',
                    href='http://docs.examples.com/api/json')


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
            raise falcon.HTTPBadRequest('Empty request body',
                                        'A valid JSON document is required.')

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
