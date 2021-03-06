# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_util -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2013-2017, Matthew Finkel
#             (c) 2007-2017, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Common utilities for BridgeDB."""

from functools import partial

import abc
import logging
import logging.config
import logging.handlers
import os
import re
import time

from twisted.python import components


def _getLogHandlers(logToFile=True, logToStderr=True):
    """Get the appropriate list of log handlers.

    :param bool logToFile: If ``True``, add a logfile handler.
    :param bool logToStderr: If ``True``, add a stream handler to stderr.
    :rtype: list
    :returns: A list containing the appropriate log handler names from the
        :class:`logging.config.dictConfigClass`.
    """
    logHandlers = []
    if logToFile:
        logHandlers.append('rotating')
    if logToStderr:
        logHandlers.append('console')
    return logHandlers

def _getRotatingFileHandler(filename, mode='a', maxBytes=1000000, backupCount=0,
                            encoding='utf-8', uid=None, gid=None):
    """Get a :class:`logging.RotatingFileHandler` with a logfile which is
    readable+writable only by the given **uid** and **gid**.

    :param str filename: The full path to the log file.
    :param str mode: The mode to open **filename** with. (default: ``'a'``)
    :param int maxBytes: Rotate logfiles after they have grown to this size in
        bytes.
    :param int backupCount: The number of logfiles to keep in rotation.
    :param str encoding: The encoding for the logfile.
    :param int uid: The owner UID to set on the logfile.
    :param int gid: The GID to set on the logfile.
    :rtype: :class:`logging.handlers.RotatingFileHandler`
    :returns: A logfile handler which will rotate files and chown/chmod newly
        created files.
    """
    # Default to the current process owner's uid and gid:
    uid = os.getuid() if not uid else uid
    gid = os.getgid() if not gid else gid

    if not os.path.exists(filename):
        open(filename, 'a').close()
    os.chown(filename, uid, gid)
    try:
        os.chmod(filename, os.ST_WRITE | os.ST_APPEND)
    except AttributeError:  # pragma: no cover
        logging.error("""
    XXX FIXME: Travis chokes on `os.ST_WRITE` saying that the module doesn't
               have that attribute, for some reason:
    https://travis-ci.org/isislovecruft/bridgedb/builds/24145963#L1601""")
        os.chmod(filename, 384)

    fileHandler = partial(logging.handlers.RotatingFileHandler,
                          filename,
                          mode,
                          maxBytes=maxBytes,
                          backupCount=backupCount,
                          encoding=encoding)
    return fileHandler

def configureLogging(cfg):
    """Set up Python's logging subsystem based on the configuration.

    :type cfg: :class:`~bridgedb.persistent.Conf`
    :param cfg: The current configuration, including any in-memory settings.
    """
    from bridgedb import safelog

    # Turn on safe logging by default:
    safelogging = getattr(cfg, 'SAFELOGGING', True)
    safelog.setSafeLogging(safelogging)

    level = getattr(cfg, 'LOGLEVEL', 'WARNING')
    logLevel = getattr(logging, level, 0)
    logStderr = getattr(cfg, 'LOG_TO_STDERR', False)
    logfileName = getattr(cfg, 'LOGFILE', "bridgedb.log")
    logfileCount = getattr(cfg, 'LOGFILE_COUNT', 3) - 1
    logfileRotateSize = getattr(cfg, 'LOGFILE_ROTATE_SIZE', 10000000)
    logThreads = getattr(cfg, 'LOG_THREADS', False)
    logTrace = getattr(cfg, 'LOG_TRACE', False)
    logTimeFormat = getattr(cfg, 'LOG_TIME_FORMAT', "%H:%M:%S")

    logFilters = []
    if safelogging:
        logFilters = ['safelogEmail', 'safelogIPv4', 'safelogIPv6']

    logConfig = {
        'version': 1,
        'filters': {
            'safelogEmail': {'()': safelog.SafelogEmailFilter},
            'safelogIPv4': {'()': safelog.SafelogIPv4Filter},
            'safelogIPv6': {'()': safelog.SafelogIPv6Filter},
        },
        'formatters': {
            'default': {'()': JustifiedLogFormatter,
                        # These values below are kwargs passed to
                        # :class:`JustifiedFormatter`:
                        'logThreads': logThreads,
                        'logTrace': logTrace,
                        'datefmt': logTimeFormat},
        },
        'handlers': {
            'console': {'class': 'logging.StreamHandler',
                        'level': logLevel,
                        'formatter': 'default',
                        'filters': logFilters},
            'rotating': {'()': _getRotatingFileHandler(logfileName, 'a',
                                                       logfileRotateSize,
                                                       logfileCount),
                         'level': logLevel,
                         'formatter': 'default',
                         'filters': logFilters},
        },
        'root': {
            'handlers': _getLogHandlers(logfileName, logStderr),
            'level': logLevel,
        },
    }

    logging.config.dictConfig(logConfig)

    logging.info("Logger Started.")
    logging.info("Level: %s", logLevel)
    logging.info("Safe Logging: %sabled" % ("En" if safelogging else "Dis"))

def deleteFilesOlderThan(files, seconds):
    """Delete any file in ``files`` with an mtime more than ``seconds`` ago.

    :param list files: A list of paths to files which should be
        considered for deletion.
    :param int seconds: If a file's mtime is more than this number (in
        seconds), it will be deleted.
    :rtype: list
    :returns: A list of the deleted files.
    """
    deleted = []
    now = int(time.time())

    for fn in files:
        if (now - os.stat(fn).st_mtime) > seconds:
            os.unlink(fn)
            deleted.append(fn)

    return deleted

def levenshteinDistance(s1, s2, len1=None, len2=None,
                        offset1=0, offset2=0, memo=None):
    """Compute the Levenstein Distance between two strings.

    The `Levenshtein String Distance Algorithm
    <https://en.wikipedia.org/wiki/Levenshtein_distance>` efficiently computes
    the number of characters which must be changed in **s1** to make it
    identical to **s2**.

    >>> from bridgedb.util import levenshteinDistance
    >>> levenshteinDistance('cat', 'cat')
    0
    >>> levenshteinDistance('cat', 'hat')
    1
    >>> levenshteinDistance('arma', 'armadillo')
    5

    :param str s1: The string which should be changed.
    :param str s2: The string which **stringOne** should be compared to.
    """
    len1 = len(s1) if len1 is None else len1
    len2 = len(s2) if len2 is None else len2
    memo = {} if memo is None else memo

    key = ','.join([str(offset1), str(len1), str(offset2), str(len2)])
    if memo.get(key) is not None: return memo[key]

    if len1 == 0: return len2
    elif len2 == 0: return len1

    cost = 0 if (s1[offset1] == s2[offset2]) else 1
    distance = min(
        levenshteinDistance(s1, s2, len1-1, len2,   offset1+1, offset2,   memo) + 1,
        levenshteinDistance(s1, s2, len1,   len2-1, offset1,   offset2+1, memo) + 1,
        levenshteinDistance(s1, s2, len1-1, len2-1, offset1+1, offset2+1, memo) + cost,
    )
    memo[key] = distance
    return distance

def isascii(s):
    """Return True if there are no non-ASCII characters in s, False otherwise.

    Note that this function differs from the str.is* methods in that
    it returns True for the empty string, rather than False.

    >>> from bridgedb.util import isascii
    >>> isascii('\x80')
    False
    >>> isascii('foo\tbar\rbaz\n')
    True
    >>> isascii('foo bar')
    True

    :param str s: The string to check for non-ASCII characters.
    """
    return all(map((lambda ch: ord(ch) < 128), s))

def isascii_noncontrol(s):
    """Return True if there are no non-ASCII or control characters in
    s, False otherwise.

    Note that this function differs from the str.is* methods in that
    it returns True for the empty string, rather than False.

    >>> from bridgedb.util import isascii_noncontrol
    >>> isascii_noncontrol('\x80')
    False
    >>> isascii_noncontrol('foo\tbar\rbaz\n')
    False
    >>> isascii_noncontrol('foo bar')
    True

    :param str s: The string to check for non-ASCII or control characters.
    """
    return all(map((lambda ch: 32 <= ord(ch) < 127), s))

def replaceControlChars(text, replacement=None, encoding="utf-8"):
    """Remove ASCII control characters [0-31, 92, 127].

    >>> from bridgedb.util import replaceControlChars
    >>> replaceControlChars('foo\n bar\\ baz\r \t\0quux\n')
    'foo bar baz quux'
    >>> replaceControlChars("\bI wonder if I'm outside the quotes now")
    "I wonder if I'm outside the quotes now"

    :param str text: Some text to remove ASCII control characters from.
    :param int replacement: If given, the **replacement** should be an integer
        representing the decimal representation of the byte to replace
        occurences of ASCII control characters with. For example, if they
        should be replaced with the character ``'a'``, then ``97`` should be
        used as the **replacement**, because ``ord('a') == 97``.
    :param str encoding: The encoding of the **text**.
    :rtype: str
    :returns: The sanitized **text**.
    """

    if replacement is None:
        replacement = ''

    # the following replaces characters 0-31, 92, and 127

    text = text.decode(encoding) if isinstance(text, bytes) else text
    return re.sub(r'[\x00-\x1f\x5c\x7f]', '', text)


def registerAdapter(adapter, adapted, interface):
    """Register a Zope interface adapter for global use.

    See :api:`twisted.python.components.registerAdapter` and the Twisted
    Matrix Labs `howto documentation for components`_.

    .. howto documentation for components:
        https://twistedmatrix.com/documents/current/core/howto/components.html
    """
    try:
        components.registerAdapter(adapter, adapted, interface)
    except ValueError:  # An adapter class was already registered
        pass


class JustifiedLogFormatter(logging.Formatter):
    """A logging formatter which pretty prints thread and calling function
    information, in addition to the normal timestamp, log level, and log
    message.

    :ivar int width: The width of the column for the calling function
        information, if the latter is to be included.
    """
    width = 30

    def __init__(self, logThreads=False, logTrace=False,
                 datefmt="%H:%M:%s"):
        """If **logTrace** is ``True``, the line number, module name, and
        function name where the logger was called will be included in the
        message, and the width of this information will always equal ``width``.

        :param bool logThreads: If ``True``, include the current thread name
            and ID in formatted log messages.
        :param bool logTrace: If ``True``, include information on the calling
            function in formatted log messages.
        """
        self.logThreads = logThreads
        self.logTrace = logTrace

        _fmt = ["%(asctime)s %(levelname)-7.7s"]
        if self.logThreads:
            _fmt.append("[%(threadName)s id:%(thread)d]")
        _fmt.append("%(callingFunc)s")
        _fmt.append("%(message)s")

        super(JustifiedLogFormatter, self).__init__(fmt = " ".join(_fmt), datefmt=datefmt)

    def _formatCallingFuncName(self, record):
        """Format the combined module name and function name of the place where
        the log message/record was recorded, so that the formatted string is
        left-justified and not longer than the :cvar:`width`.

        :type record: :class:`logging.LogRecord`
        :param record: A record of an event created by calling a logger.
        :returns: The :class:`logging.LogRecord` with its ``message``
            attribute rewritten to contain the module and function name,
            truncated to ``width``, or padded on the right with spaces as is
            necessary.
        """
        callingFunc = ""
        if self.logTrace:
            # The '.' character between the module name and function name
            # would otherwise be interpreted as a format string specifier, so
            # we must specify ``chr(46)``:
            lineno = "L%s:" % record.lineno
            caller = "%s%-s%s" % (lineno.rjust(6), record.module, chr(46))
            maxFuncNameWidth = self.width - 2 - len(caller)
            funcName = record.funcName
            if len(funcName) > maxFuncNameWidth:
                funcName = record.funcName[:maxFuncNameWidth]
            caller += "%s()" % (funcName)
            callingFunc = caller.ljust(self.width)

        record.callingFunc = callingFunc
        return record

    def format(self, record):
        """Reformat this log **record** to neatly print thread and function
        traces, if configured to do so.

        :type record: :class:`logging.LogRecord`
        :param record: A record of an event created by calling a logger.
        """
        record = self._formatCallingFuncName(record)
        return super(JustifiedLogFormatter, self).format(record)


class mixin(metaclass=abc.ABCMeta):
    """Subclasses of me can be used as a mixin class by registering another
    class, ``ClassA``, which should be mixed with the ``mixin`` subclass, in
    order to provide simple, less error-prone, multiple inheritance models::

    >>> from __future__ import print_function
    >>> from bridgedb.util import mixin
    >>>
    >>> class ClassA(object):
    ...     def sayWhich(self):
    ...         print("ClassA.sayWhich() called.")
    ...     def doSuperThing(self):
    ...         print("%s" % super(ClassA, self))
    ...     def doThing(self):
    ...         print("ClassA is doing a thing.")
    ...
    >>> class ClassB(ClassA):
    ...     def sayWhich(self):
    ...         print("ClassB.sayWhich() called.")
    ...     def doSuperThing(self):
    ...         print("%s" % super(ClassB, self))
    ...     def doOtherThing(self):
    ...         print("ClassB is doing something else.")
    ...
    >>> class ClassM(mixin):
    ...     def sayWhich(self):
    ...         print("ClassM.sayWhich() called.")
    ...
    >>> ClassM.register(ClassA)
    >>>
    >>> class ClassC(ClassM, ClassB):
    ...     def sayWhich(self):
    ...         super(ClassC, self).sayWhich()
    ...
    >>> c = ClassC()
    >>> c.sayWhich()
    ClassM.sayWhich() called.
    >>> c.doSuperThing()
    <super: <class 'ClassB'>, <ClassC object>>
    >>> c.doThing()
    ClassA is doing a thing.
    >>> c.doOtherThing()
    ClassB is doing something else.

    .. info:: This class' name is lowercased because pylint is hardcoded to
        expect mixin classes to end in ``'mixin'``.
    """
