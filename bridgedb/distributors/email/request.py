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
from bridgedb.distributors.email.distributor import EmailNoTransportSpecified
from bridgedb.distributors.email.distributor import EmailNoCountryCode


def determineBridgeRequestOptions(lines):
    """Figure out which :mod:`~bridgedb.filters` to apply, or offer help.

    .. note:: If any ``'transport TYPE'`` was requested, or bridges not
        blocked in a specific CC (``'unblocked CC'``), then the ``TYPE``
        and/or ``CC`` will *always* be stored as a *lowercase* string.

    :param list lines: A list of lines from an email, excluding the headers.
    :raises EmailRequestedHelp: if the client requested help.
    :raises EmailRequestedKey: if the client requested our GnuPG key.
    :rtype: :class:`EmailBridgeRequest`
    :returns: A :class:`~bridgerequest.BridgeRequest` with all of the requested
        parameters set. The returned ``BridgeRequest`` will have already had
        its filters generated via :meth:`~EmailBridgeRequest.generateFilters`.
    """
    request = EmailBridgeRequest()
    msg = email.message_from_string('\n'.join(lines),policy=policy.compat32)
    """If the parsing with get_payload() was succesfull, it will return a list 
    which can be parsed further to extract the payload only
    If the parsing with get_payload() was not succesfull, it will return
    the entire message as a string. This might happen in some testcases that
    do not generate a valid email to parse. In this case it will check for 
    the Subject header and look for the string 'testing' and continue parsing
    from there on."""
    if type(msg.get_payload()) is list:
        lines = msg.get_payload(0).get_payload().split()
    else:
        payload = msg.get_payload().split()
        testing = False
        newlines = []
        for line in payload:
            if testing == True and line != '""':
                newlines.append(line)
            if "testing" in line.strip().lower():
                testing = True
        lines = newlines

    skipindex = 0
    for i, line in enumerate(lines):
        if i < skipindex:
            continue
        line = line.strip().lower()

        if line == "get":
            request.isValid(True) 
        elif line == "help" or line == "halp":
            raise EmailRequestedHelp("Client requested help.")         
        elif line == "key":
            request.wantsKey(True)
            raise EmailRequestedKey("Email requested a copy of our GnuPG key.")
        elif line == "ipv6":
            request.withIPv6()
        elif line == "transport":
            if i < len(lines):
                skipindex = i+request.withPluggableTransportType(lines,i+1)+1
            else:
                raise EmailNoTransportSpecified("Email does not specify a transport protocol.")
        elif line == "unblocked":
            if i < len(lines):
                skipindex = i+request.withoutBlockInCountry(lines,i+1)+1
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

    def withoutBlockInCountry(self, lines, i):
        """This request was for bridges not blocked in **country**.

        Add any country code found in the **line** to the list of
        ``notBlockedIn``. Currently, a request for a transport is recognized
        if the email line contains the ``'unblocked'`` command.

        :param list lines: A list of lines (in this case words) from an email
        :param int i: Index on where to continue parsing the lines list to 
        obtain the country codes
        """
        countrymatch = False
        skipindex = 0
        for country in lines[i:]:
            if len(country) == 2:
                self.notBlockedIn.append(country)
                logging.info("Email requested bridges not blocked in: %r"
                             % country)            
                countrymatch = True
                skipindex += 1        
            else:
                if countrymatch == False:
                    raise EmailNoCountryCode("Email did not specify a country code.")
                break             
        return skipindex

    def withPluggableTransportType(self, lines, i):
        """This request included a specific Pluggable Transport identifier.

        Add any Pluggable Transport method TYPE found in the **line** to the
        list of ``transports``. Currently, a request for a transport is
        recognized if the email line contains the ``'transport'`` command.

        :param list lines: A list of lines (in this case words) from an email
        :param int i: Index on where to continue parsing the lines list to 
        obtain the requested transport protocol.
        """
        transport_protocols = {"obfs2", "obfs3","obfs4","fte","scramblesuit","vanilla"}
        protocolmatch = False
        skipindex = 0
        for protocol in lines[i:]:
            protocol = protocol.strip().lower()
            if protocol in transport_protocols:
                self.transports.append(protocol)
                protocolmatch = True
                skipindex += 1
                logging.info("Email requested transport type: %r" % protocol)
            else:
                if protocolmatch == False:
                    raise EmailNoTransportSpecified("Email does not specify a transport protocol.")
                break    
        return skipindex           
