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
import copy

from bridgedb import metrics
from bridgedb.test import util
from bridgedb.test.https_helpers import DummyRequest
from bridgedb.distributors.email.server import SMTPMessage
from bridgedb.distributors.https.server import HTTPSBridgeRequest
from bridgedb.test.email_helpers import _createMailServerContext
from bridgedb.test.email_helpers import _createConfig
from bridgedb.distributors.moat import server
from bridgedb.bridges import Bridge

from twisted.trial import unittest
from twisted.test import proto_helpers


class StateTest(unittest.TestCase):

    def setUp(self):
        self.topDir = os.getcwd().rstrip('_trial_temp')
        self.captchaDir = os.path.join(self.topDir, 'captchas')

        # Clear all singletons before each test to prevent cross-test
        # interference.
        type(metrics.HTTPSMetrics()).clear()
        type(metrics.EmailMetrics()).clear()
        type(metrics.MoatMetrics()).clear()
        type(metrics.InternalMetrics()).clear()

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
        message.lines = [
            "From: foo@gmail.com",
            "To: bridges@torproject.org",
            "Subject: testing",
            "",
            "get transport obfs4",
        ]

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

    def test_bridge_handouts(self):

        metrix = metrics.InternalMetrics()
        bridges = copy.deepcopy(util.generateFakeBridges())
        bridge1, bridge2, bridge3 = bridges[0:3]
        m = metrix.hotMetrics

        br = HTTPSBridgeRequest()
        br.withIPversion({"ipv6": "4"})

        # Record a number of distribution events for three separate bridges.
        for i in range(10):
            metrix.recordHandoutsPerBridge(br, [bridge1])
        for i in range(5):
            metrix.recordHandoutsPerBridge(br, [bridge2])
        metrix.recordHandoutsPerBridge(br, [bridge3])

        self.assertEqual(m["internal.handouts.unique-bridges"], 3)
        self.assertEqual(m["internal.handouts.min"], 1)
        self.assertEqual(m["internal.handouts.max"], 10)
        self.assertEqual(m["internal.handouts.median"], 5)

        # Internal metrics must not be sanitized.
        metrix.rotate()
        lines = metrix.getMetrics()
        self.assertIn("internal.handouts.unique-bridges 3", lines)
        self.assertIn("internal.handouts.median 5", lines)
        self.assertIn("internal.handouts.min 1", lines)
        self.assertIn("internal.handouts.max 10", lines)

    def test_empty_responses(self):

        metrix = metrics.InternalMetrics()

        # Unlike all other internal metrics, empty responses are sanitized.
        for i in range(10):
            metrix.recordEmptyEmailResponse()
        for i in range(11):
            metrix.recordEmptyMoatResponse()
        metrix.recordEmptyHTTPSResponse()

        metrix.rotate()
        lines = metrix.getMetrics()

        self.assertEqual(len(lines), 3)
        self.assertIn("internal.email.empty-response 10", lines)
        self.assertIn("internal.moat.empty-response 20", lines)
        self.assertIn("internal.https.empty-response 10", lines)

    def test_rings(self):

        metrix = metrics.InternalMetrics()

        # Empty parameters must not be recorded.
        metrix.recordBridgesInHashring("", "", 20)
        self.assertEqual(len(metrix.hotMetrics), 0)

        metrix.recordBridgesInHashring("https", "byIPv6-bySubring1of4", 20)
        self.assertEqual(len(metrix.hotMetrics), 1)
        self.assertEqual(list(metrix.hotMetrics.keys()),
                         ["internal.https.byipv6-bysubring1of4"])

    def test_ipv4_ipv6_requests(self):

        metrix = metrics.InternalMetrics()
        v6Req = HTTPSBridgeRequest()
        v6Req.withIPversion({"ipv6": "4"})
        v4Req = HTTPSBridgeRequest()
        v4Req.withIPversion({})

        bridges = copy.deepcopy(util.generateFakeBridges())

        for i in range(9):
            metrix.recordHandoutsPerBridge(v6Req, [bridges[0]])
        metrix.recordHandoutsPerBridge(v6Req, [bridges[1]])

        for i in range(11):
            metrix.recordHandoutsPerBridge(v4Req, [bridges[0]])

        metrix.rotate()
        lines = metrix.getMetrics()

        self.assertIn("internal.handouts.ipv6 10", lines)
        self.assertIn("internal.handouts.ipv4 20", lines)

    def test_handouts(self):

        metrix = metrics.InternalMetrics()
        metrix.recordHandoutsPerBridge(None, None)
        self.assertEqual(len(metrix.hotMetrics), 0)

        req = HTTPSBridgeRequest()
        req.withIPversion({})
        bridges = copy.deepcopy(util.generateFakeBridges())

        metrix.recordHandoutsPerBridge(req, [bridges[0]])
        self.assertNotIn("internal.handouts.median", metrix.hotMetrics.keys())
        metrix.recordHandoutsPerBridge(req, [bridges[1]])
        self.assertNotIn("internal.handouts.median", metrix.hotMetrics.keys())
        metrix.recordHandoutsPerBridge(req, [bridges[2]])
        self.assertEqual(metrix.hotMetrics["internal.handouts.median"], 1)

        metrix.recordHandoutsPerBridge(req, [bridges[1]])
        metrix.recordHandoutsPerBridge(req, [bridges[2]])
        metrix.recordHandoutsPerBridge(req, [bridges[2]])
        self.assertEqual(metrix.hotMetrics["internal.handouts.min"], 1)
        self.assertEqual(metrix.hotMetrics["internal.handouts.median"], 2)
        self.assertEqual(metrix.hotMetrics["internal.handouts.max"], 3)
        self.assertEqual(metrix.hotMetrics["internal.handouts.unique-bridges"], 3)
        self.assertEqual(metrix.hotMetrics["internal.handouts.stdev"], 1)