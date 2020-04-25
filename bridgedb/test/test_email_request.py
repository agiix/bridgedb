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

"""Unittests for the :mod:`bridgedb.distributors.email.request` module."""

from __future__ import print_function

import ipaddr

from twisted.trial import unittest

from bridgedb.distributors.email import request

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


class DetermineBridgeRequestOptionsTests(unittest.TestCase):
    """Unittests for :func:`b.e.request.determineBridgeRequestOptions`."""

    def test_determineBridgeRequestOptions_get_help(self):
        """Requesting 'get help' should raise EmailRequestedHelp."""
        lines = mail.copy()
        lines[73] = 'get help'
        self.assertRaises(request.EmailRequestedHelp,
                          request.determineBridgeRequestOptions, lines)
        
    def test_determineBridgeRequestOptions_get_halp(self):
        """Requesting 'get halp' should raise EmailRequestedHelp."""
        lines = mail.copy()
        lines[73] = 'get halp'
        self.assertRaises(request.EmailRequestedHelp,
                          request.determineBridgeRequestOptions, lines)
        
    def test_determineBridgeRequestOptions_get_key(self):
        """Requesting 'get key' should raise EmailRequestedKey."""
        lines = mail.copy()
        lines[73] = 'get key'
        self.assertRaises(request.EmailRequestedKey,
                          request.determineBridgeRequestOptions, lines)

    def test_determineBridgeRequestOptions_multiline_invalid(self):
        """Requests without a 'get' anywhere should be considered invalid."""
        lines = mail.copy()
        lines[73] = ''
        lines.insert(74,'transport obfs3')
        lines.insert(75,'ipv6 vanilla bridges')
        lines.insert(76,'give me your gpgs')
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's invalid because it didn't include a 'get' anywhere.
        self.assertEqual(reqvest.isValid(), False)
        self.assertFalse(reqvest.wantsKey())
        # Though they did request IPv6, technically.
        self.assertIs(reqvest.ipVersion, 6)
        # And they did request a transport, technically.
        self.assertEqual(len(reqvest.transports), 1)
        self.assertEqual(reqvest.transports[0], 'obfs3')

    #def test_determineBridgeRequestOptions_multiline_valid(self):
        """Though requests with a 'get' are considered valid."""
        """Not defined yet
        lines = mail.copy()
        lines[73] = ''
        lines.insert(74,'transport obfs3')
        lines.insert(75,'vanilla bridges'')
        lines.insert(76,'transport scramblesuit unblocked ca)
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's valid because it included a 'get'.
        self.assertEqual(reqvest.isValid(), True)
        self.assertFalse(reqvest.wantsKey())
        # Though they didn't request IPv6, so it should default to IPv4.
        self.assertIs(reqvest.ipVersion, 4)
        # And they requested two transports.
        self.assertEqual(len(reqvest.transports), 2)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.transports[1], 'scramblesuit')
        # And they wanted this stuff to not be blocked in Canada.
        self.assertEqual(len(reqvest.notBlockedIn), 1)
        self.assertEqual(reqvest.notBlockedIn[0], 'ca')"""

    #def test_determineBridgeRequestOptions_multiline_valid_OMG_CAPSLOCK(self):
        """Though requests with a 'get' are considered valid, even if they
        appear to not know the difference between Capslock and Shift.
        """
        """Not defined yet
        lines = ['',
                 'get TRANSPORT obfs3',
                 'vanilla bridges',
                 'TRANSPORT SCRAMBLESUIT UNBLOCKED CA']
        reqvest = request.determineBridgeRequestOptions(lines)
        # It's valid because it included a 'get'.
        self.assertEqual(reqvest.isValid(), True)
        self.assertFalse(reqvest.wantsKey())
        # Though they didn't request IPv6, so it should default to IPv4.
        self.assertIs(reqvest.ipVersion, 4)
        # And they requested two transports.
        self.assertEqual(len(reqvest.transports), 2)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.transports[1], 'scramblesuit')
        # And they wanted this stuff to not be blocked in Canada.
        self.assertEqual(len(reqvest.notBlockedIn), 1)
        self.assertEqual(reqvest.notBlockedIn[0], 'ca')"""

    def test_determineBridgeRequestOptions_get_transport(self):
        """An invalid request for 'transport obfs3' (missing the 'get')."""
        lines = mail.copy()
        lines[73] = 'transport obfs3'
        reqvest = request.determineBridgeRequestOptions(lines)
        self.assertEqual(len(reqvest.transports), 1)
        self.assertEqual(reqvest.transports[0], 'obfs3')
        self.assertEqual(reqvest.isValid(), False)
        
    def test_determineBridgeRequestOptions_get_ipv6(self):
        """An valid request for 'get ipv6'."""
        lines = mail.copy()
        lines[73] = ''
        lines.insert(74,'get ipv6')
        reqvest = request.determineBridgeRequestOptions(lines)
        self.assertIs(reqvest.ipVersion, 6)
        self.assertEqual(reqvest.isValid(), True)


class EmailBridgeRequestTests(unittest.TestCase):
    """Unittests for :class:`b.e.request.EmailBridgeRequest`."""

    def setUp(self):
        """Create an EmailBridgeRequest instance to test."""
        self.request = request.EmailBridgeRequest()

    def tearDown(self):
        """Reset cached 'unblocked'/'transport' lists and ipVersion between
        tests.
        """
        self.request.withIPv4()
        self.request.notBlockedIn = []
        self.request.transports = []

    def test_EmailBridgeRequest_isValid_initial(self):
        """Initial value of EmailBridgeRequest.isValid() should be False."""
        self.request.isValid(None)
        self.assertEqual(self.request.isValid(), False)

    def test_EmailBridgeRequest_isValid_True(self):
        """The value of EmailBridgeRequest.isValid() should be True, after it
        has been called with ``True`` as an argument.
        """
        self.request.isValid(True)
        self.assertEqual(self.request.isValid(), True)

    def test_EmailBridgeRequest_isValid_False(self):
        """The value of EmailBridgeRequest.isValid() should be False, after it
        has been called with ``False`` as an argument.
        """
        self.request.isValid(False)
        self.assertEqual(self.request.isValid(), False)

    def test_EmailBridgeRequest_wantsKey_initial(self):
        """Initial value of EmailBridgeRequest.wantsKey() should be False."""
        self.request.wantsKey(None)
        self.assertEqual(self.request.wantsKey(), False)

    def test_EmailBridgeRequest_wantsKey_True(self):
        """The value of EmailBridgeRequest.wantsKey() should be True, after it
        has been called with ``True`` as an argument.
        """
        self.request.wantsKey(True)
        self.assertEqual(self.request.wantsKey(), True)

    def test_EmailBridgeRequest_wantsKey_False(self):
        """The value of EmailBridgeRequest.wantsKey() should be False, after
        it has been called with ``False`` as an argument.
        """
        self.request.wantsKey(False)
        self.assertEqual(self.request.wantsKey(), False)

    def test_EmailBridgeRequest_withIPv6(self):
        """IPv6 requests should have ``ipVersion == 6``."""
        self.assertEqual(self.request.ipVersion, 4)
        self.request.withIPv6()
        self.assertEqual(self.request.ipVersion, 6)

    #def test_EmailBridgeRequest_withoutBlockInCountry_CN(self):
        """Country codes that aren't lowercase should be ignored."""
        """Uppercase country codes will currently not be ignored
        self.request.withoutBlockInCountry('CN')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 0)"""

    def test_EmailBridgeRequest_withoutBlockInCountry_cn(self):
        """Lowercased country codes are okay though."""
        countries = ['cn']
        self.request.withoutBlockInCountry(countries,0)
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)

    def test_EmailBridgeRequest_withoutBlockInCountry_cn_getMissing(self):
        """Lowercased country codes are still okay if the 'get' is missing."""
        countries = ['cn']
        self.request.withoutBlockInCountry(countries,0)
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)

    def test_EmailBridgeRequest_withoutBlockInCountry_multiline_cn_ir_li(self):
        """Requests for multiple unblocked countries should compound if they
        are on separate 'get unblocked' lines.
        """
        countries = ['cn','ir','li']
        self.request.withoutBlockInCountry(countries,0)        
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 3)

    #def test_EmailBridgeRequest_withoutBlockInCountry_singleline_cn_ir_li(self):
        """Requests for multiple unblocked countries which are all on the same
        'get unblocked' line will use only the *first* country code.
        """
        """Not possible with the current parsing method, since it will only check for one country code
        after the keyword unblocked
        self.request.withoutBlockInCountry('get unblocked cn ir li')
        self.assertIsInstance(self.request.notBlockedIn, list)
        self.assertEqual(len(self.request.notBlockedIn), 1)"""

    #def test_EmailBridgeRequest_withPluggableTransportType_SCRAMBLESUIT(self):
        """Transports which aren't in lowercase should be ignored."""
        """Uppercase protocols will currently not be ignored
        self.request.withPluggableTransportType('SCRAMBLESUIT')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 0)"""

    def test_EmailBridgeRequest_withPluggableTransportType_scramblesuit(self):
        """Lowercased transports are okay though."""
        protocols = ['scramblesuit']
        self.request.withPluggableTransportType(protocols,0)
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'scramblesuit')

    def test_EmailBridgeRequest_withPluggableTransportType_scramblesuit_getMissing(self):
        """Lowercased transports are still okay if 'get' is missing."""
        protocols = ['scramblesuit']
        self.request.withPluggableTransportType(protocols,0)
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'scramblesuit')

    def test_EmailBridgeRequest_withPluggableTransportType_multiline_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple pluggable transports should compound if they
        are on separate 'get transport' lines.
        """
        protocols = ['obfs3','obfs2','scramblesuit']
        self.request.withPluggableTransportType(protocols,0)
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 3)
        self.assertEqual(self.request.transports[0], 'obfs3')

    #def test_EmailBridgeRequest_withPluggableTransportType_singleline_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple transports which are all on the same
        'get transport' line will use only the *first* transport.
        """
        """Not possible with the current parsing method, since it will only check for one transport protocol
        after the keyword transport
        self.request.withPluggableTransportType('get transport obfs3 obfs2 scramblesuit')
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 1)
        self.assertEqual(self.request.transports[0], 'obfs3')"""

    def test_EmailBridgeRequest_withPluggableTransportType_whack(self):
        """Requests for whacky transports that don't should not be appended."""
        arguments = ['whack',0]
        self.assertRaises(request.EmailNoTransportSpecified,
                          self.request.withPluggableTransportType, arguments)


    def test_EmailBridgeRequest_justOnePTType_obfs3_obfs2_scramblesuit(self):
        """Requests for multiple transports when
        ``EmailBridgeRequest.justOneTransport()`` is used will use only the
        *last* transport.
        """
        protocols = ['obfs3','obfs2','scramblesuit']
        self.request.withPluggableTransportType(protocols,0)
        self.assertIsInstance(self.request.transports, list)
        self.assertEqual(len(self.request.transports), 3)
        self.assertEqual(self.request.transports[0], 'obfs3')
        self.assertEqual(self.request.justOnePTType(), 'scramblesuit')
