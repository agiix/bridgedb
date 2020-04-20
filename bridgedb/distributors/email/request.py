# -*- coding: utf-8; test-case-name: bridgedb.test.test_email_request; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson <nickm@torproject.org>
#           Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
#           Matthew Finkel <sysrqb@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2013-2017, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""
.. py:module:: bridgedb.distributors.email.request
    :synopsis: Classes for parsing and storing information about requests for
               bridges which are sent to the email distributor.

bridgedb.distributors.email.request
======================

Classes for parsing and storing information about requests for bridges
which are sent to the email distributor.

.. inheritance-diagram:: EmailBridgeRequest
    :parts: 1

::

  bridgedb.distributors.email.request
   | |_ determineBridgeRequestOptions - Figure out which filters to apply, or
   |                                    offer help.
   |_ EmailBridgeRequest - A request for bridges which was received through
                           the email distributor.

..
"""

from __future__ import print_function
from __future__ import unicode_literals

import logging
import email
from email import policy

from bridgedb import bridgerequest
from bridgedb.distributors.email.distributor import EmailRequestedHelp
from bridgedb.distributors.email.distributor import EmailRequestedKey


def determineBridgeRequestOptions(lines):
    """Figure out which :mod:`~bridgedb.filters` to apply, or offer help.

    .. note:: If any ``'transport TYPE'`` was requested, or bridges not
        blocked in a specific CC (``'unblocked CC'``), then the ``TYPE``
        and/or ``CC`` will *always* be stored as a *lowercase* string.

    :param list lines: A list of lines from an email, including the headers.
    :raises EmailRequestedHelp: if the client requested help.
    :raises EmailRequestedKey: if the client requested our GnuPG key.
    :rtype: :class:`EmailBridgeRequest`
    :returns: A :class:`~bridgerequest.BridgeRequest` with all of the requested
        parameters set. The returned ``BridgeRequest`` will have already had
        its filters generated via :meth:`~EmailBridgeRequest.generateFilters`.
    """
    request = EmailBridgeRequest()
    msg = email.message_from_string('\n'.join(lines),policy=policy.compat32)
    if type(msg.get_payload()) is list:
        lines = msg.get_payload(0).get_payload().split()
    else:
        payload = msg.get_payload().split()
        testing = False
        newlines = []
        for line in testlines:
            if testing == True and line != '""':
                newlines.append(line)
            if "testing" in line.strip().lower():
                testing = True
        lines = newlines
    skip = False
    """TODO: in case of transport or blocked the next index in the loop needs to be skipped, othwerwise the loop will break"""
    for i, line in enumerate(lines):
        if skip == True: 
            skip = False
            continue
        line = line.strip().lower()

        if line == "get":
            request.isValid(True) 
            continue
        elif line == "help" or line == "halp":
            raise EmailRequestedHelp("Client requested help.")         
        elif line == "key":
            request.wantsKey(True)
            raise EmailRequestedKey("Email requested a copy of our GnuPG key.")
        elif line == "ipv6":
            request.withIPv6()
        elif line == "transport":
            if i < len(lines):
                request.withPluggableTransportType(lines[i+1])
                skip = True
            else:
                raise EmailNoTransportSpecified("Email does not specify a transport protocol.")
        elif line == "unblocked":
            if i < len(lines):
                request.withoutBlockInCountry(lines[i+1])
                skip = True
            else:
                raise EmailNoCountryCode("Email did not specify a country code.")
        else:
            break

    logging.debug("Generating hashring filters for request.")
    request.generateFilters()
    return request


class EmailBridgeRequest(bridgerequest.BridgeRequestBase):
    """We received a request for bridges through the email distributor."""

    def __init__(self):
        """Process a new bridge request received through the
        :class:`~bridgedb.distributors.email.distributor.EmailDistributor`.
        """
        super(EmailBridgeRequest, self).__init__()
        self._wantsKey = False

    def wantsKey(self, wantsKey=None):
        """Get or set whether this bridge request wanted our GnuPG key.

        If called without parameters, this method will return the current
        state, otherwise (if called with the **wantsKey** parameter set), it
        will set the current state for whether or not this request wanted our
        key.

        :param bool wantsKey: If given, set the validity state of this
            request. Otherwise, get the current state.
        """
        if wantsKey is not None:
            self._wantsKey = bool(wantsKey)
        return self._wantsKey

    def withoutBlockInCountry(self, line):
        """This request was for bridges not blocked in **country**.

        Add any country code found in the **line** to the list of
        ``notBlockedIn``. Currently, a request for a transport is recognized
        if the email line contains the ``'unblocked'`` command.

        :param str country: The line from the email wherein the client
            requested some type of Pluggable Transport.
        """
        self.notBlockedIn.append(line)
        logging.info("Email requested bridges not blocked in: %r"
                     % line)

    def withPluggableTransportType(self, line):
        """This request included a specific Pluggable Transport identifier.

        Add any Pluggable Transport method TYPE found in the **line** to the
        list of ``transports``. Currently, a request for a transport is
        recognized if the email line contains the ``'transport'`` command.

        :param str line: The line from the email wherein the client
            requested some type of Pluggable Transport.
        """
        self.transports.append(line)
        logging.info("Email requested transport type: %r" % line)
