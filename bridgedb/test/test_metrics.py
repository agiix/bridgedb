# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_metrics ; -*-
# _____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see included AUTHORS file
# :copyright: (c) 2019, The Tor Project, Inc.
#             (c) 2019, Philipp Winter
# :license: see LICENSE for licensing information
# _____________________________________________________________________________

"""Unittests for the :mod:`bridgedb.metrics` module.

These tests are meant to ensure that the :mod:`bridgedb.metrics` module is
functioning as expected.
"""

import io
import json
import os

from bridgedb import metrics
from bridgedb.test.https_helpers import DummyRequest
from bridgedb.distributors.email.server import SMTPMessage
from bridgedb.test.email_helpers import _createMailServerContext
from bridgedb.test.email_helpers import _createConfig
from bridgedb.distributors.moat import server

from twisted.trial import unittest
from twisted.test import proto_helpers

mail = ['Delivered-To: bridges@tortest.org',
'Received: by 2002:a05:6602:13d4:0:0:0:0 with SMTP id o20csp2120992iov;',
'        Sat, 18 Apr 2020 10:46:14 -0700 (PDT)',
'X-Received: by 2002:a17:906:9494:: with SMTP id t20mr8335871ejx.51.1587231973984;',
'        Sat, 18 Apr 2020 10:46:13 -0700 (PDT)',
'ARC-Seal: i=1; a=rsa-sha256; t=1587231973; cv=none;',
'        d=tortest.org; s=arc-20160816;',
'        b=P++gupCMle0gEDuiOC97BZ73JV9jpGZ5FGDSaU6XCcpqRUUJQqGlXc88xtzL7iqV3K',
'         x+Hs2WTpfVaS5fAYMqY7MD4RyVLv0yzRRnA1d/JXMBDBPydD+FUqyLlt04AG/+R5W6Hd',
'         6IbkC0f2vatBC0J/3A3sqDDoOHSSMx++BdCa76OSRtChiDayc0KTlBFafwJ58Yntdylo',
'         VHCBD8T9eyiEOctHHzCHUx2JMmDaa1Mi8mj0WSxMUxUl6GntFL7ELMSGriQbutuCgLPk',
'         lcPKcyCEfVlwSpJc+SGyvW8MoCJVROVnkLmYKxLYrwDMTzF6+eUku+vTI0VEtPGOp2J8',
'         kkjg==',
'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=tortest.org; s=arc-20160816;',
'        h=to:subject:message-id:date:from:mime-version:dkim-signature;',
'        bh=bGAfoz3V4Jo7aM4K+tXFmdSxzqmIPLMt8hH0zv25iC4=;',
'        b=XTvn86uetPgooCDFYA9PoiRlZpp2Kf1mWymCFe9vlXqkd1vvPy/Q0bAH3Pj3C9trNm',
'         QxP+ozkCw0lLvqRhFmAbxbi+pz+rP1YZH/c73F0jYxq0uM8dlBXxcnJgYkQ5YQfwql8M',
'         kwi08uhTZ70xkwsnq0xkyH00iSLEcR3++p+4yFtwWB0aPqoVyVbdxRuN5QWczECQ897b',
'         Wt22bch+EECXsQJzhfjPHVF9GWSddxd/IsF3mUkeVGmESX74yd0EKWvw7RrqqN7ktWvb',
'         AQTCK82cNsL/hlOqFuCFCIlMlcjqsX3IDAp8voUaArl4vwcZFPlfvj0SZc+PnKsQDpSN',
'         6Bjg==',
'ARC-Authentication-Results: i=1; mx.tortest.org;',
'       dkim=pass header.i=@tortest.org header.s=20161025 header.b=dnKseKKK;',
'       spf=pass (example.com: domain of user@example.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=user@example.com;',
'       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=example.com',
'Return-Path: <user@example.com>',
'Received: from mail-sor-f41.tortest.org (mail-sor-f41.tortest.org. [209.85.220.41])',
'        by mx.tortest.org with SMTPS id k15sor8971328ejx.14.2020.04.18.10.46.13',
'        for <bridges@tortest.org>',
'        (Google Transport Security);',
'        Sat, 18 Apr 2020 10:46:13 -0700 (PDT)',
'Received-SPF: pass (example.com: domain of user@example.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;',
'Authentication-Results: mx.example.com;',
'       dkim=pass header.i=@example.com header.s=20161025 header.b=dnKseKKK;',
'       spf=pass (example.com: domain of user@example.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=user@example.com;',
'       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=example.com',
'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;',
'        d=example.com; s=20161025;',
'        h=mime-version:from:date:message-id:subject:to;',
'        bh=bGAfoz3V4Jo7aM4K+tXFmdSxzqmIPLMt8hH0zv25iC4=;',
'        b=dnKseKKKZ7d7Z/bvTrwP3ZSxd91nqHC8dwSn6UHPVu+eD8Ke43K/lmtWKofTUHudtA',
'         mQKK1+jtJy9o1+UgY0ZOHiYi/h9fzRF6mH5aMDUfUWO4yJYROC/sZeW3an3Jy0i+Cdrd',
'         TV9W8P4FqfRjxJo/01NXd8hqg8qZtZWASacPI6j+B7eJltUmkWVFWfPNyDxb57GLkaEa',
'         7p4S9bL50ArlRAGT0wwTok0hhrNUgfQVfBdUiPiP0ACXbKSAWQCzaEJsd+TmwFpzKNt1',
'         EuHv+ae0kwBXnKZbcbj6p5RCKjWuDTcp0/9fY2t8Wf6VLHZ3J50aHiXSjXabbyq/4qFs',
'         Dohg==',
'X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;',
'        d=1e100.net; s=20161025;',
'        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;',
'        bh=bGAfoz3V4Jo7aM4K+tXFmdSxzqmIPLMt8hH0zv25iC4=;',
'        b=ga/FK2aWV3csNHHFZRjSd0UqnJ/COjSgKZpKHFdXvK3UQTpD0/slGbOgCPiJfV3cnG',
'         lwJAcPqHA/7RTNmuB7z9O7K2iW/0C+Kw6vdfMImCQIJEOqazqmPRQpAxHv3aAQy8eWuK',
'         6as6RkAN8du01qxZ0ni/XCzPWaop5+spOJqy4bvG8lbch3fNsuTfc0oPmVqMNH9jNtEK',
'         MwOo1o8dR9qvxvPzLtoHc/UOX+LzB3vPqxDZhVftgScDjtEZJ0lhy30j/kgoT4UyAb8j',
'         YWawJhlkTMyVSQQOXc0g6nh9EzOHrTf1LkWhE3QtUrKIFx1gXrEJ3HCfc+DYajzLfbwt',
'         0W5w==',
'X-Gm-Message-State: AGi0PuZiNB23KPSM3218BJ+ejDtFOPoxrppWlcZQeMr/W/nrlHbDHLSx',
'	qlkG3KwOxibUYhWjjIqX6vjv9ssCICutisRpgc4yoSgJ',
'X-Google-Smtp-Source: APiQypIqfkeHyhDpaI7rV9Tv3BYYu6rKuC29wUw7HYU+MXfA2tILZGUFaF70BgURZf7KQn3eNjXM1j2pWkrX8Iu/fR4=',
'X-Received: by 2002:a17:906:b7da:: with SMTP id fy26mr8934480ejb.327.1587231973509;',
' Sat, 18 Apr 2020 10:46:13 -0700 (PDT)',
'MIME-Version: 1.0',
'From: User <user@example.com>',
'Date: Sat, 18 Apr 2020 19:46:02 +0200',
'Message-ID: <CANv2OEusjGMY5x9_z5O2=Rg1AjKqUOfSng+sBRheH37U5hq84Q@mail.example.com>',
'Subject:', 
'To: "bridges@tortest.org" <bridges@tortest.org>',
'Content-Type: multipart/alternative; boundary="000000000000f50d9a05a3943d32"',
'',
'--000000000000f50d9a05a3943d32',
'Content-Type: text/plain; charset="UTF-8"',
'',
'get transport obfs4',
'',
'--000000000000f50d9a05a3943d32',
'Content-Type: text/html; charset="UTF-8"',
'Content-Transfer-Encoding: quoted-printable',
'',
'<div dir=3D"auto">get transport obfs4=C2=A0<br></div><div dir=3D"auto"><br>=',
'</div>',
'',
'--000000000000f50d9a05a3943d32--']


class StateTest(unittest.TestCase):

    def setUp(self):
        self.topDir = os.getcwd().rstrip('_trial_temp')
        self.captchaDir = os.path.join(self.topDir, 'captchas')

        # Clear all singletons before each test to prevent cross-test
        # interference.
        type(metrics.HTTPSMetrics()).clear()
        type(metrics.EmailMetrics()).clear()
        type(metrics.MoatMetrics()).clear()

        metrics.setSupportedTransports({
            'obfs2': False,
            'obfs3': True,
            'obfs4': True,
            'scramblesuit': True,
            'fte': True,
        })

        self.metrix = metrics.HTTPSMetrics()
        self.key = self.metrix.createKey("https", "obfs4", "de", True, None)

    def test_binning(self):

        key = self.metrix.createKey("https", "obfs4", "de", True, None)
        self.metrix.coldMetrics = self.metrix.hotMetrics

        # A value of 1 should be rounded up to 10.
        self.metrix.inc(key)
        metrixLines = self.metrix.getMetrics()
        key, value = metrixLines[0].split(" ")
        self.assertTrue(int(value) == 10)

        # A value of 10 should remain 10.
        self.metrix.set(key, 10)
        metrixLines = self.metrix.getMetrics()
        key, value = metrixLines[0].split(" ")
        self.assertTrue(int(value) == 10)

        # A value of 11 should be rounded up to 20.
        self.metrix.inc(key)
        metrixLines = self.metrix.getMetrics()
        key, value = metrixLines[0].split(" ")
        self.assertTrue(int(value) == 20)

    def test_key_manipulation(self):

        self.metrix = metrics.HTTPSMetrics()
        key = self.metrix.createKey("email", "obfs4", "de", True, "none")
        self.assertTrue(key == "email.obfs4.de.success.none")

        self.metrix.inc(key)
        self.assertEqual(self.metrix.hotMetrics[key], 1)

        self.metrix.set(key, 10)
        self.assertEqual(self.metrix.hotMetrics[key], 10)

    def test_rotation(self):

        key = self.metrix.createKey("moat", "obfs4", "de", True, "none")
        self.metrix.inc(key)
        oldHotMetrics = self.metrix.hotMetrics
        self.metrix.rotate()

        self.assertEqual(len(self.metrix.coldMetrics), 1)
        self.assertEqual(len(self.metrix.hotMetrics), 0)
        self.assertEqual(self.metrix.coldMetrics, oldHotMetrics)

    def test_export(self):

        self.metrix.inc(self.key)

        self.metrix.coldMetrics = self.metrix.hotMetrics
        pseudo_fh = io.StringIO()
        metrics.export(pseudo_fh, 0)

        self.assertTrue(len(pseudo_fh.getvalue()) > 0)

        lines = pseudo_fh.getvalue().split("\n")
        self.assertTrue(lines[0].startswith("bridgedb-metrics-end"))
        self.assertTrue(lines[1].startswith("bridgedb-metrics-version"))
        self.assertTrue(lines[2] ==
                        "bridgedb-metric-count https.obfs4.de.success.None 10")

    def test_https_metrics(self):

        origFunc = metrics.resolveCountryCode
        metrics.resolveCountryCode = lambda _: "US"

        key1 = "https.obfs4.us.success.none"
        req1 = DummyRequest([b"bridges?transport=obfs4"])
        # We have to set the request args manually when using a DummyRequest.
        req1.args.update({'transport': ['obfs4']})
        req1.getClientIP = lambda: "3.3.3.3"

        self.metrix.recordValidHTTPSRequest(req1)
        self.assertTrue(self.metrix.hotMetrics[key1] == 1)

        key2 = "https.obfs4.us.fail.none"
        req2 = DummyRequest([b"bridges?transport=obfs4"])
        # We have to set the request args manually when using a DummyRequest.
        req2.args.update({'transport': ['obfs4']})
        req2.getClientIP = lambda: "3.3.3.3"
        self.metrix.recordInvalidHTTPSRequest(req2)
        self.assertTrue(self.metrix.hotMetrics[key2] == 1)

        metrics.resolveCountryCode = origFunc

    def test_email_metrics(self):
        
        config = _createConfig()
        context = _createMailServerContext(config)
        message = SMTPMessage(context)
        message.lines = mail.copy()
        message.lines[63] = 'From: foo@gmail.com'
        message.lines[67] = 'To: bridges@localhost'
        message.lines[66] = 'Subject: testing'
        message.lines[73] = 'get bridges'
        message.message = message.getIncomingMessage()
        responder = message.responder
        tr = proto_helpers.StringTransportWithDisconnection()
        tr.protocol = responder
        responder.makeConnection(tr)

        email_metrix = metrics.EmailMetrics()

        key1 = "email.obfs4.gmail.success.none"
        email_metrix.recordValidEmailRequest(responder)
        self.assertTrue(email_metrix.hotMetrics[key1] == 1)

        key2 = "email.obfs4.gmail.fail.none"
        email_metrix.recordInvalidEmailRequest(responder)
        self.assertTrue(email_metrix.hotMetrics[key2] == 1)

    def test_moat_metrics(self):

        def create_moat_request():
            encoded_data = json.dumps({
                'data': [{
                    'id': '2',
                    'type': 'moat-solution',
                    'version': server.MOAT_API_VERSION,
                    'transport': 'obfs4',
                    'solution': 'Tvx74PMy',
                    'qrcode': False,
                }]
            })

            request = DummyRequest(["fetch"])
            request.requestHeaders.addRawHeader('Content-Type',
                                                'application/vnd.api+json')
            request.requestHeaders.addRawHeader('Accept',
                                                'application/vnd.api+json')
            request.requestHeaders.addRawHeader('X-Forwarded-For', '3.3.3.3')
            request.headers['X-Forwarded-For'.lower()] = '3.3.3.3'
            request.method = b'POST'
            request.writeContent(encoded_data)

            return request

        metrix = metrics.MoatMetrics()
        metrix.recordValidMoatRequest(create_moat_request())
        metrix.recordInvalidMoatRequest(create_moat_request())

        key1 = "moat.obfs4.us.success.none"
        key2 = "moat.obfs4.us.fail.none"
        self.assertTrue(metrix.hotMetrics[key1] == 1)
        self.assertTrue(metrix.hotMetrics[key2] == 1)

    def test_is_bridge_type_supported(self):

        oldTransports = metrics.SUPPORTED_TRANSPORTS
        metrics.setSupportedTransports({})
        self.assertFalse(metrics.isBridgeTypeSupported("obfs4"))
        metrics.setSupportedTransports(oldTransports)

        self.assertTrue(metrics.isBridgeTypeSupported("obfs4"))
        self.assertTrue(metrics.isBridgeTypeSupported("vanilla"))
        self.assertFalse(metrics.isBridgeTypeSupported("xxx"))
