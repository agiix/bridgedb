# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.distributors.email.autoresponder` module."""

from __future__ import print_function

import io
import os
import shutil

from twisted.internet import defer
from twisted.mail.smtp import Address
from twisted.python.failure import Failure
from twisted.trial import unittest
from twisted.test import proto_helpers

from bridgedb.distributors.email import autoresponder
from bridgedb.distributors.email.server import SMTPMessage
from bridgedb.distributors.email.distributor import TooSoonEmail

from bridgedb.test.email_helpers import _createConfig
from bridgedb.test.email_helpers import _createMailServerContext
from bridgedb.test.email_helpers import DummyEmailDistributorWithState

import email
from email import policy

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


class CreateResponseBodyTests(unittest.TestCase):
    """Tests for :func:`bridgedb.distributors.email.autoresponder.createResponseBody`."""

    def _moveGPGTestKeyfile(self):
        here          = os.getcwd()
        topDir        = here.rstrip('_trial_temp')
        self.gpgFile  = os.path.join(topDir, '.gnupg', 'TESTING.subkeys.sec')
        self.gpgMoved = os.path.join(here, 'TESTING.subkeys.sec')
        shutil.copy(self.gpgFile, self.gpgMoved)

    def setUp(self):
        """Create fake email, distributor, and associated context data."""
        self._moveGPGTestKeyfile()
        self.toAddress = 'user@example.com'
        self.config = _createConfig()
        self.ctx = _createMailServerContext(self.config)
        self.distributor = self.ctx.distributor

    def _getIncomingLines(self, clientAddress="user@example.com",line=None):
        """Generate the lines of an incoming email from **clientAddress**."""
        self.toAddress = Address(clientAddress)
        lines = mail.copy()
        lines[63] = 'From: %s' % clientAddress
        lines[67] = 'To: bridges@localhost'
        lines[66] = 'Subject: testing'
        if line is not None:
            lines[73] = line
        else:
            lines[73] = 'get bridges'
        return email.message_from_string('\n'.join(lines),policy=policy.compat32)

    #def test_createResponseBody_getKey(self):
        """A request for 'get key' should receive our GPG key.
        lines = self._getIncomingLines("user@example.com","get key")
        ret = autoresponder.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring('-----BEGIN PGP PUBLIC KEY BLOCK-----', ret)"""

    def test_createResponseBody_bridges_invalid(self):
        """An invalid request for 'transport obfs3' should get help text."""
        lines = self._getIncomingLines("testing@localhost",'transport obfs3')
        ret = autoresponder.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("COMMANDs", ret)

    def test_createResponseBody_bridges_obfs3(self):
        """A request for 'get transport obfs3' should receive a response."""
        lines = self._getIncomingLines("testing@localhost","get transport obfs3")
        ret = autoresponder.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs3", ret)

    #def test_createResponseBody_bridges_obfsobfsbz(self):
        """We should only pay attention to the *last* in a crazy request.
        Commented out this test case for now, Needs to be adjusted

        lines = mail.copy
        lines[73] = 'get unblocked bz'
        lines.insert(74,'get transport obfs2')
        lines.insert(75,'get transport obfs3')
        lines = self._getIncomingLinesInsertLines("testing@localhost",lines)
        ret = autoresponder.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs3", ret)"""

    #def test_createResponseBody_bridges_obfsobfswebzipv6(self):
        """We should *still* only pay attention to the *last* request."""
        """Will fail since the new parsing method currently can not invalid a whole line
        lines = self._getIncomingLines("testing@localhost")
        lines[73] = 'transport obfs3'
        lines.insert(74,'get unblocked webz')
        lines.insert(75,'get ipv6"')
        lines.insert(76,'get transport obfs2')
        ret = autoresponder.createResponseBody(lines, self.ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", ret)
        self.assertSubstring("obfs2", ret)"""

    def test_createResponseBody_two_requests_TooSoonEmail(self):
        """The same client making two requests in a row should receive a
        rate-limit warning for the second response.
        """
        # Set up a mock distributor which keeps state:
        dist = DummyEmailDistributorWithState()
        ctx = _createMailServerContext(self.config, dist)

        lines = self._getIncomingLines("testing@localhost")
        first = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", first)
        second = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertSubstring("Please slow down", second)

    def test_createResponseBody_three_requests_TooSoonEmail(self):
        """Alice making a request, next Bob making a request, and then Alice again,
        should result in both of their first requests getting them bridges,
        and then Alice's second request gets her a rate-limit warning email.
        """
        # Set up a mock distributor which keeps state:
        dist = DummyEmailDistributorWithState()
        ctx = _createMailServerContext(self.config, dist)

        aliceLines = self._getIncomingLines("alice@localhost")
        aliceFirst = autoresponder.createResponseBody(aliceLines, ctx,
                                                      self.toAddress)
        self.assertSubstring("Here are your bridges", aliceFirst)

        bobLines = self._getIncomingLines("bob@localhost")
        bobFirst = autoresponder.createResponseBody(bobLines, ctx,
                                                    self.toAddress)
        self.assertSubstring("Here are your bridges", bobFirst)

        aliceSecond = autoresponder.createResponseBody(aliceLines, ctx,
                                                       self.toAddress)
        self.assertSubstring("Please slow down", aliceSecond)

    def test_createResponseBody_three_requests_IgnoreEmail(self):
        """The same client making three requests in a row should receive a
        rate-limit warning for the second response, and then nothing for every
        request thereafter.
        """
        # Set up a mock distributor which keeps state:
        dist = DummyEmailDistributorWithState()
        ctx = _createMailServerContext(self.config, dist)

        lines = self._getIncomingLines("testing@localhost")
        first = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertSubstring("Here are your bridges", first)
        second = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertSubstring("Please slow down", second)
        third = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertIsNone(third)
        fourth = autoresponder.createResponseBody(lines, ctx, self.toAddress)
        self.assertIsNone(fourth)


class EmailResponseTests(unittest.TestCase):
    """Tests for ``generateResponse()`` and ``EmailResponse``."""

    def setUp(self):
        self.fromAddr = "bridges@torproject.org"
        self.clientAddr = "user@example.com"
        self.body = """\
People think that time is strictly linear, but, in reality, it's actually just
a ball of timey-wimey, wibbly-warbly... stuff."""

    def tearDown(self):
        autoresponder.safelog.safe_logging = True

    def test_EmailResponse_generateResponse(self):
        response = autoresponder.generateResponse(self.fromAddr,
                                                  self.clientAddr,
                                                  self.body)
        self.assertIsInstance(response, autoresponder.EmailResponse)

    def test_EmailResponse_generateResponse_noSafelog(self):
        autoresponder.safelog.safe_logging = False
        response = autoresponder.generateResponse(self.fromAddr,
                                                  self.clientAddr,
                                                  self.body)
        self.assertIsInstance(response, autoresponder.EmailResponse)

    def test_EmailResponse_generateResponse_mailfile(self):
        response = autoresponder.generateResponse(self.fromAddr,
                                                  self.clientAddr,
                                                  self.body)
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))

    def test_EmailResponse_generateResponse_withInReplyTo(self):
        response = autoresponder.generateResponse(self.fromAddr,
                                                  self.clientAddr,
                                                  self.body,
                                                  messageID="NSA")
        contents = str(response.readContents()).replace('\x00', '')
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))
        self.assertSubstring("In-Reply-To: NSA", contents)

    def test_EmailResponse_generateResponse_readContents(self):
        response = autoresponder.generateResponse(self.fromAddr,
                                                  self.clientAddr,
                                                  self.body)
        contents = str(response.readContents()).replace('\x00', '')
        self.assertSubstring('timey-wimey, wibbly-warbly... stuff.', contents)

    def test_EmailResponse_additionalHeaders(self):
        response = autoresponder.EmailResponse()
        response.writeHeaders(self.fromAddr, self.clientAddr,
                              subject="Re: echelon", inReplyTo="NSA",
                              X_been_there="They were so 2004")
        contents = str(response.readContents()).replace('\x00', '')
        self.assertIsInstance(response.mailfile, (io.BytesIO, io.StringIO))
        self.assertSubstring("In-Reply-To: NSA", contents)
        self.assertSubstring("X-been-there: They were so 2004", contents)

    def test_EmailResponse_close(self):
        """Calling EmailResponse.close() should close the ``mailfile`` and set
        ``closed=True``.
        """
        response = autoresponder.EmailResponse()
        self.assertEqual(response.closed, False)
        response.close()
        self.assertEqual(response.closed, True)
        self.assertRaises(ValueError, response.write, self.body)

    def test_EmailResponse_read(self):
        """Calling EmailResponse.read() should read bytes from the file."""
        response = autoresponder.EmailResponse()
        response.write(self.body)
        response.rewind()
        contents = response.read().replace(b'\x00', b'').decode('utf-8')
        # The newlines in the email body should have been replaced with
        # ``EmailResponse.delimiter``.
        delimited = self.body.replace('\n', response.delimiter) \
                    + response.delimiter
        self.assertEqual(delimited, contents)

    def test_EmailResponse_read_three_bytes(self):
        """EmailResponse.read(3) should read three bytes from the file."""
        response = autoresponder.EmailResponse()
        response.write(self.body)
        response.rewind()
        contents = response.read(3).replace(b'\x00', b'').decode('utf-8')
        self.assertEqual(contents, self.body[:3])

    def test_EmailResponse_write(self):
        """Calling EmailResponse.write() should write to the mailfile."""
        response = autoresponder.EmailResponse()
        response.write(self.body)
        contents = str(response.readContents()).replace('\x00', '')
        # The newlines in the email body should have been replaced with
        # ``EmailResponse.delimiter``.
        delimited = self.body.replace('\n', response.delimiter) \
                    + response.delimiter
        self.assertEqual(delimited, contents)

    def test_EmailResponse_write_withRetNewlines(self):
        """Calling EmailResponse.write() with '\r\n' in the lines should call
        writelines(), which splits up the lines and then calls write() again.
        """
        response = autoresponder.EmailResponse()
        response.write(self.body.replace('\n', '\r\n'))
        contents = str(response.readContents()).replace('\x00', '')
        # The newlines in the email body should have been replaced with
        # ``EmailResponse.delimiter``.
        delimited = self.body.replace('\n', response.delimiter) \
                    + response.delimiter
        self.assertEqual(delimited, contents)

    def test_EmailResponse_writelines_list(self):
        """Calling EmailResponse.writelines() with a list should write the
        concatenated contents of the list into the mailfile.
        """
        response = autoresponder.EmailResponse()
        response.writelines(self.body.split('\n'))
        contents = str(response.readContents()).replace('\x00', '')
        # The newlines in the email body should have been replaced with
        # ``EmailResponse.delimiter``.
        delimited = self.body.replace('\n', response.delimiter) \
                    + response.delimiter
        self.assertEqual(delimited, contents)


class SMTPAutoresponderTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.distributors.email.autoresponder.SMTPAutoresponder`."""

    timeout = 10

    def setUp(self):
        self.config = _createConfig()
        self.context = _createMailServerContext(self.config)
        self.message = SMTPMessage(self.context)

    def _getIncomingLines(self, clientAddress="user@example.com"):
        """Generate the lines of an incoming email from **clientAddress**."""
        lines = [
            "From: %s" % clientAddress,
            "To: bridges@localhost",
            "Subject: testing",
            "",
            "get bridges",
        ]
        """lines = mail
        lines[63] = 'From: %s' % clientAddress
        lines[67] = 'To: bridges@localhost'
        lines[66] = 'Subject: testing'
        lines[73] = 'get bridges'"""
        self.message.lines = lines

    def _setUpResponder(self):
        """Set up the incoming message of our autoresponder.

        This is necessary because normally our SMTP server acts as a line
        protocol, waiting for an EOM which sets off a chain of deferreds
        resulting in the autoresponder sending out the response. This should
        be called after :meth:`_getIncomingLines` so that we can hook into the
        SMTP protocol without actually triggering all the deferreds.
        """
        self.message.message = self.message.getIncomingMessage()
        self.responder = self.message.responder
        # The following are needed to provide client disconnection methods for
        # the call to ``twisted.mail.smtp.SMTPClient.sendError`` in
        # ``bridgedb.distributors.email.autoresponder.SMTPAutoresponder.sendError``:
        #protocol = proto_helpers.AccumulatingProtocol()
        #transport = proto_helpers.StringTransportWithDisconnection()
        self.tr = proto_helpers.StringTransportWithDisconnection()
        # Set the transport's protocol, because
        # StringTransportWithDisconnection is a bit janky:
        self.tr.protocol = self.responder
        self.responder.makeConnection(self.tr)

    def test_SMTPAutoresponder_getMailFrom_notbridgedb_at_yikezors_dot_net(self):
        """SMTPAutoresponder.getMailFrom() for an incoming email sent to any email
        address other than the one we're listening for should return our
        configured address, not the one in the incoming email.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: notbridgedb@yikezors.net'
        self._setUpResponder()
        recipient = str(self.responder.getMailFrom())
        self.assertEqual(recipient, self.context.fromAddr)

    def test_SMTPAutoresponder_getMailFrom_givemebridges_at_seriously(self):
        """SMTPAutoresponder.getMailFrom() for an incoming email sent to any email
        address other than the one we're listening for should return our
        configured address, not the one in the incoming email.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: givemebridges@serious.ly'
        self._setUpResponder()
        recipient = str(self.responder.getMailFrom())
        self.assertEqual(recipient, self.context.fromAddr)

    def test_SMTPAutoresponder_getMailFrom_bad_address(self):
        """SMTPAutoresponder.getMailFrom() for an incoming email sent to a malformed
        email address should log an smtp.AddressError and then return our
        configured email address.
        """
        self._getIncomingLines()
        self.message.lines[1] = 'To: ><@><<<>>.foo'
        self._setUpResponder()
        recipient = str(self.responder.getMailFrom())
        self.assertEqual(recipient, self.context.fromAddr)

    def test_SMTPAutoresponder_getMailFrom_plus_address(self):
        """SMTPAutoresponder.getMailFrom() for an incoming email sent with a valid
        plus address should respond.
        """
        self._getIncomingLines()
        ours = Address(self.context.fromAddr)
        plus = '@'.join([ours.local.decode('utf-8') + '+zh_cn', ours.domain.decode('utf-8')])
        self.message.lines[1] = 'To: {0}'.format(plus)
        self._setUpResponder()
        recipient = str(self.responder.getMailFrom())
        self.assertEqual(recipient, plus)

    def test_SMTPAutoresponder_getMailFrom_getbridges_at_localhost(self):
        """SMTPAutoresponder.getMailFrom() for an incoming email sent with
        'getbridges+zh_cn@localhost' should be responded to from the default
        address.
        """
        self._getIncomingLines()
        ours = Address(self.context.fromAddr)
        plus = '@'.join(['get' + ours.local.decode('utf-8') + '+zh_cn', ours.domain.decode('utf-8')])
        self.message.lines[1] = 'To: {0}'.format(plus)
        self._setUpResponder()
        recipient = str(self.responder.getMailFrom())
        self.assertEqual(recipient, self.context.fromAddr)

    def test_SMTPAutoresponder_getMailTo_UnsupportedDomain(self):
        """getMailTo() should catch emails from UnsupportedDomains."""
        emailFrom = 'some.dude@un.support.ed'
        self._getIncomingLines(emailFrom)
        self._setUpResponder()
        clients = self.responder.getMailTo()
        self.assertIsInstance(clients, list, (
            "Returned value of SMTPAutoresponder.getMailTo() isn't a list! "
            "Type: %s" % type(clients)))
        self.assertTrue(emailFrom not in clients)
        # The client was from an unsupported domain; they shouldn't be in the
        # clients list:
        self.assertEqual(len(clients), 0,
                         "clients = %s" % repr(clients))

    def test_SMTPAutoresponder_reply_noFrom(self):
        """A received email without a "From:" or "Sender:" header shouldn't
        receive a response.
        """
        self._getIncomingLines()
        self.message.lines[0] = ""
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_badAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing*.?\"@example.com")
        self._setUpResponder()
        ret = self.responder.reply()
        # This will call ``self.responder.reply()``:
        #ret = self.responder.incoming.eomReceived()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_anotherBadAddress(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("Mallory <>>@example.com")
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_invalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing@exa#mple.com")
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_anotherInvalidDomain(self):
        """Don't respond to RFC2822 malformed source addresses."""
        self._getIncomingLines("testing@exam+ple.com")
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_DKIM_badDKIMheader(self):
        """An email with an 'X-DKIM-Authentication-Result:' header appended
        after the body should not receive a response.
        """
        self._getIncomingLines("testing@gmail.com")
        self.message.lines.append("X-DKIM-Authentication-Result: ")
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_goodDKIMheader(self):
        """An email with a good DKIM header should be responded to."""
        self._getIncomingLines("testing@gmail.com")
        self.message.lines.insert(3, "X-DKIM-Authentication-Result: pass")
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)

    def test_SMTPAutoresponder_reply_transport_invalid(self):
        """An invalid request for 'transport obfs3' should get help text."""
        #self.skip = True
        #raise unittest.SkipTest("We need to fake the reactor for this one")

        def cb(success):
            pass
        self._getIncomingLines("testing@example.com")
        self.message.lines[4] = "transport obfs3"
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)
        #self.assertSubstring("COMMANDs", ret)
        print(self.tr.value())
        return ret

    def test_SMTPAutoresponder_reply_transport_valid(self):
        """An valid request for 'get transport obfs3' should get obfs3."""
        #self.skip = True
        #raise unittest.SkipTest("We need to fake the reactor for this one")
    
        self._getIncomingLines("testing@example.com")
        self.message.lines[4] = "transport obfs3"
        self._setUpResponder()
        ret = self.responder.reply()
        self.assertIsInstance(ret, defer.Deferred)
        #self.assertSubstring("obfs3", ret)
        print(self.tr.value())
        return ret

    def test_SMTPAutoresponder_sentMail(self):
        """``SMTPAutoresponder.sendMail()`` should handle successes from an
        :api:`twisted.mail.smtp.SMTPSenderFactory`.
        """
        success = (1, [('me@myaddress.com', 250, 'OK',)])
        self._getIncomingLines()
        self._setUpResponder()
        self.responder.sentMail(success)

    def test_SMTPAutoresponder_sendError_fail(self):
        """``SMTPAutoresponder.sendError()`` should handle failures."""
        fail = Failure(ValueError('This failure was sent on purpose.'))
        self._getIncomingLines()
        self._setUpResponder()
        self.responder.sendError(fail)

    def test_SMTPAutoresponder_sendError_exception(self):
        """``SMTPAutoresponder.sendError()`` should handle exceptions."""
        error = ValueError('This error was sent on purpose.')
        self._getIncomingLines()
        self._setUpResponder()
        self.responder.sendError(error)

    def test_SMTPAutoresponder_runChecks_RCPTTO_From_mismatched_domain(self):
        """runChecks() should catch emails where the SMTP 'MAIL FROM:' command
        reported being from an email address at one supported domain and the
        email's 'From:' header reported another domain.
        """
        smtpFrom = 'not.an.evil.bot@riseup.net'
        emailFrom = Address('not.an.evil.bot@gmail.com')
        self._getIncomingLines(str(emailFrom))
        self._setUpResponder()
        self.responder.incoming.canonicalFromSMTP = smtpFrom
        self.assertFalse(self.responder.runChecks(emailFrom))

    def test_SMTPAutoresponder_runChecks_RCPTTO_From_mismatched_username(self):
        """runChecks() should catch emails where the SMTP 'MAIL FROM:' command
        reported being from an email address and the email's 'From:' header
        reported another email address, even if the only the username part is
        mismatched.
        """
        smtpFrom = 'feidanchaoren0001@gmail.com'
        emailFrom = Address('feidanchaoren0038@gmail.com')
        self._getIncomingLines(str(emailFrom))
        self._setUpResponder()
        self.responder.incoming.canonicalFromSMTP = smtpFrom
        self.assertFalse(self.responder.runChecks(emailFrom))

    def test_SMTPAutoresponder_runChecks_DKIM_dunno(self):
        """runChecks() should catch emails with bad DKIM headers
        (``"X-DKIM-Authentication-Results: dunno"``) for canonical domains
        which we're configured to check DKIM verification results for.
        """
        emailFrom = Address('dkimlikedunno@gmail.com')
        header = "X-DKIM-Authentication-Results: dunno"
        self._getIncomingLines(str(emailFrom))
        self.message.lines.insert(3, header)
        self._setUpResponder()
        self.assertFalse(self.responder.runChecks(emailFrom))

    def test_SMTPAutoresponder_runChecks_DKIM_bad(self):
        """runChecks() should catch emails with bad DKIM headers
        (``"X-DKIM-Authentication-Results: dunno"``) for canonical domains
        which we're configured to check DKIM verification results for.
        """
        emailFrom = Address('dkimlikewat@gmail.com')
        header = "X-DKIM-Authentication-Results: wowie zowie there's a sig here"
        self._getIncomingLines(str(emailFrom))
        self.message.lines.insert(3, header)
        self._setUpResponder()
        self.assertFalse(self.responder.runChecks(emailFrom))

    def test_SMTPAutoresponder_runChecks_blacklisted(self):
        """runChecks() on an blacklisted email address should return False."""
        emailFrom = Address('feidanchaoren0043@gmail.com')
        self._getIncomingLines(str(emailFrom))
        self._setUpResponder()
        self.assertFalse(self.responder.runChecks(emailFrom))
