""" Multicast DNS Service Discovery for Python, v0.12
    Copyright (C) 2003, Paul Scott-Murphy

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.  It has been tested against the JRendezvous
    implementation from <a href="http://strangeberry.com">StrangeBerry</a>,
    and against the mDNSResponder from Mac OS X 10.3.8.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""

"""0.12 update - allow selection of binding interface
         typo fix - Thanks A. M. Kuchlingi
         removed all use of word 'Rendezvous' - this is an API change"""

"""0.11 update - correction to comments for addListener method
                 support for new record types seen from OS X
                  - IPv6 address
                  - hostinfo
                 ignore unknown DNS record types
                 fixes to name decoding
                 works alongside other processes using port 5353 (e.g. on Mac OS X)
                 tested against Mac OS X 10.3.2's mDNSResponder
                 corrections to removal of list entries for service browser"""

"""0.10 update - Jonathon Paisley contributed these corrections:
                 always multicast replies, even when query is unicast
                 correct a pointer encoding problem
                 can now write records in any order
                 traceback shown on failure
                 better TXT record parsing
                 server is now separate from name
                 can cancel a service browser

                 modified some unit tests to accommodate these changes"""

"""0.09 update - remove all records on service unregistration
                 fix DOS security problem with readName"""

"""0.08 update - changed licensing to LGPL"""

"""0.07 update - faster shutdown on engine
                 pointer encoding of outgoing names
                 ServiceBrowser now works
                 new unit tests"""

"""0.06 update - small improvements with unit tests
                 added defined exception types
                 new style objects
                 fixed hostname/interface problem
                 fixed socket timeout problem
                 fixed addServiceListener() typo bug
                 using select() for socket reads
                 tested on Debian unstable with Python 2.2.2"""

"""0.05 update - ensure case insensitivty on domain names
                 support for unicast DNS queries"""

"""0.04 update - added some unit tests
                 added __ne__ adjuncts where required
                 ensure names end in '.local.'
                 timeout on receiving socket for clean shutdown"""

__author__ = "Paul Scott-Murphy"
__email__ = "paul at scott dash murphy dot com"
__version__ = "0.12"


import string
import time
import struct
import socket
import threading
import select
import traceback
import logging
import mcastsocket
log = logging.getLogger(__name__)
from zeroconf.dns import *

__all__ = ["Zeroconf", "ServiceInfo", "ServiceBrowser"]

# hook for threads

globals()['_GLOBAL_DONE'] = 0

# Some timing constants

_UNREGISTER_TIME = 125
_CHECK_TIME = 175
_REGISTER_TIME = 225
_LISTENER_TIME = 200
_BROWSER_TIME = 500

# Some DNS constants

_MDNS_ADDR = '224.0.0.251'
_MDNS_PORT = 5353;
_DNS_PORT = 53;
_DNS_TTL = 60 * 60; # one hour default TTL

_MAX_MSG_TYPICAL = 1460 # unused
_MAX_MSG_ABSOLUTE = 8972

_FLAGS_QR_MASK = 0x8000 # query response mask
_FLAGS_QR_QUERY = 0x0000 # query
_FLAGS_QR_RESPONSE = 0x8000 # response

_FLAGS_AA = 0x0400 # Authorative answer
_FLAGS_TC = 0x0200 # Truncated
_FLAGS_RD = 0x0100 # Recursion desired
_FLAGS_RA = 0x8000 # Recursion available

_FLAGS_Z = 0x0040 # Zero
_FLAGS_AD = 0x0020 # Authentic data
_FLAGS_CD = 0x0010 # Checking disabled

_CLASS_IN = 1
_CLASS_CS = 2
_CLASS_CH = 3
_CLASS_HS = 4
_CLASS_NONE = 254
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF
_CLASS_UNIQUE = 0x8000

_TYPE_A = 1
_TYPE_NS = 2
_TYPE_MD = 3
_TYPE_MF = 4
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_MB = 7
_TYPE_MG = 8
_TYPE_MR = 9
_TYPE_NULL = 10
_TYPE_WKS = 11
_TYPE_PTR = 12
_TYPE_HINFO = 13
_TYPE_MINFO = 14
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY =  255

# Mapping constants to names

_CLASSES = { _CLASS_IN : "in",
             _CLASS_CS : "cs",
             _CLASS_CH : "ch",
             _CLASS_HS : "hs",
             _CLASS_NONE : "none",
             _CLASS_ANY : "any" }

_TYPES = { _TYPE_A : "a",
           _TYPE_NS : "ns",
           _TYPE_MD : "md",
           _TYPE_MF : "mf",
           _TYPE_CNAME : "cname",
           _TYPE_SOA : "soa",
           _TYPE_MB : "mb",
           _TYPE_MG : "mg",
           _TYPE_MR : "mr",
           _TYPE_NULL : "null",
           _TYPE_WKS : "wks",
           _TYPE_PTR : "ptr",
           _TYPE_HINFO : "hinfo",
           _TYPE_MINFO : "minfo",
           _TYPE_MX : "mx",
           _TYPE_TXT : "txt",
           _TYPE_AAAA : "quada",
           _TYPE_SRV : "srv",
           _TYPE_ANY : "any" }

# utility functions

def currentTimeMillis():
    """Current system time in milliseconds"""
    return time.time() * 1000

# Exceptions

class NonLocalNameException(Exception):
    pass

class NonUniqueNameException(Exception):
    pass

class NamePartTooLongException(Exception):
    pass

class AbstractMethodException(Exception):
    pass

class BadTypeInNameException(Exception):
    pass

class Engine(threading.Thread):
    """An engine wraps read access to sockets, allowing objects that
    need to receive data from sockets to be called back when the
    sockets are ready.

    A reader needs a handle_read() method, which is called when the socket
    it is interested in is ready for reading.

    Writers are not implemented here, because we only send short
    packets.
    """

    def __init__(self, zeroconf):
        threading.Thread.__init__(self)
        self.zeroconf = zeroconf
        self.readers = {} # maps socket to reader
        self.timeout = 5
        self.condition = threading.Condition()
        self.start()

    def run(self):
        while not globals()['_GLOBAL_DONE']:
            rs = self.getReaders()
            if len(rs) == 0:
                # No sockets to manage, but we wait for the timeout
                # or addition of a socket
                #
                log.debug( 'No sockets, waiting %s', self.timeout )
                self.condition.acquire()
                self.condition.wait(self.timeout/25.)
                self.condition.release()
            else:
                try:
                    rr, wr, er = select.select(rs, [], [], self.timeout)
                except Exception, err:
                    log.warn( 'Select failure, ignored: %s', err )
                else:
                    for socket in rr:
                        try:
                            self.readers[socket].handle_read()
                        except Exception, err:
                            # Ignore errors that occur on shutdown
                            log.error( 'Error handling read: %s', err )
                            log.debug( 'Traceback: %s', traceback.format_exc())

    def getReaders(self):
        result = []
        self.condition.acquire()
        result = self.readers.keys()
        self.condition.release()
        return result

    def addReader(self, reader, socket):
        self.condition.acquire()
        self.readers[socket] = reader
        self.condition.notify()
        self.condition.release()

    def delReader(self, socket):
        self.condition.acquire()
        del(self.readers[socket])
        self.condition.notify()
        self.condition.release()

    def notify(self):
        self.condition.acquire()
        self.condition.notify()
        self.condition.release()

class Listener(object):
    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is availble for reading."""
    def __init__(self, zeroconf):
        self.zeroconf = zeroconf
        self.zeroconf.engine.addReader(self, self.zeroconf.socket)

    def handle_read(self):
        try:
            data, (addr, port) = self.zeroconf.socket.recvfrom(_MAX_MSG_ABSOLUTE)
        except Exception, err:
            log.info( 'Error on recvfrom: %s', err )
            return None
        self.data = data
        msg = DNSIncoming(data)
        if msg.isQuery():
            # Always multicast responses
            #
            if port == _MDNS_PORT:
                self.zeroconf.handleQuery(msg, _MDNS_ADDR, _MDNS_PORT)
            # If it's not a multicast query, reply via unicast
            #
            # and multicast
            elif port == _DNS_PORT:
                self.zeroconf.handleQuery(msg, addr, port)
                self.zeroconf.handleQuery(msg, _MDNS_ADDR, _MDNS_PORT)
            else:
                log.error(
                    "Unknown port: %s", port
                )
        else:
            self.zeroconf.handleResponse(msg)

class Reaper(threading.Thread):
    """A Reaper is used by this module to remove cache entries that
    have expired."""

    def __init__(self, zeroconf):
        threading.Thread.__init__(self)
        self.zeroconf = zeroconf
        self.daemon = True
        self.start()

    def run(self):
        while 1:
            try:
                self.zeroconf.wait(10 * 1000)
            except ValueError, err:
                break
            if globals()['_GLOBAL_DONE']:
                return
            now = currentTimeMillis()
            for record in self.zeroconf.cache.entries():
                if record.isExpired(now):
                    self.zeroconf.updateRecord(now, record)
                    self.zeroconf.cache.remove(record)


class ServiceBrowser(threading.Thread):
    """Used to browse for a service of a specific type.

    The listener object will have its addService() and
    removeService() methods called when this browser
    discovers changes in the services availability."""

    def __init__(self, zeroconf, type, listener):
        """Creates a browser for a specific type"""
        threading.Thread.__init__(self)
        self.zeroconf = zeroconf
        self.type = type
        self.listener = listener
        self.daemon = True
        self.services = {}
        self.nextTime = currentTimeMillis()
        self.delay = _BROWSER_TIME
        self.list = []

        self.done = 0

        self.zeroconf.addListener(self, DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))
        self.start()

    def updateRecord(self, zeroconf, now, record):
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache."""
        if record.type == _TYPE_PTR and record.name == self.type:
            expired = record.isExpired(now)
            try:
                oldrecord = self.services[record.alias.lower()]
                if not expired:
                    oldrecord.resetTTL(record)
                else:
                    del(self.services[record.alias.lower()])
                    callback = lambda x: self.listener.removeService(x, self.type, record.alias)
                    self.list.append(callback)
                    return
            except:
                if not expired:
                    self.services[record.alias.lower()] = record
                    callback = lambda x: self.listener.addService(x, self.type, record.alias)
                    self.list.append(callback)

            expires = record.getExpirationTime(75)
            if expires < self.nextTime:
                self.nextTime = expires

    def cancel(self):
        self.done = 1
        self.zeroconf.notifyAll()

    def run(self):
        while 1:
            event = None
            now = currentTimeMillis()
            if len(self.list) == 0 and self.nextTime > now:
                self.zeroconf.wait(self.nextTime - now)
            if globals()['_GLOBAL_DONE'] or self.done:
                return
            now = currentTimeMillis()

            if self.nextTime <= now:
                out = DNSOutgoing(_FLAGS_QR_QUERY)
                out.addQuestion(DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))
                for record in self.services.values():
                    if not record.isExpired(now):
                        out.addAnswerAtTime(record, now)
                self.zeroconf.send(out)
                self.nextTime = now + self.delay
                self.delay = min(20 * 1000, self.delay * 2)

            if len(self.list) > 0:
                event = self.list.pop(0)

            if event is not None:
                event(self.zeroconf)

class Zeroconf(object):
    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
    """
    def __init__(self, bindaddress=None):
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads."""
        globals()['_GLOBAL_DONE'] = 0
        if bindaddress is None:
            self.intf = socket.gethostbyname(socket.gethostname())
            bindaddress = self.intf
        else:
            self.intf = bindaddress
        self.socket = mcastsocket.create_socket( (bindaddress, _MDNS_PORT) )
        mcastsocket.join_group( self.socket, _MDNS_ADDR )

        self.listeners = []
        self.browsers = []
        self.services = {}

        self.cache = DNSCache()

        self.condition = threading.Condition()

        self.engine = Engine(self)
        self.listener = Listener(self)
        self.reaper = Reaper(self)

    def isLoopback(self):
        return self.intf.startswith("127.0.0.1")

    def isLinklocal(self):
        return self.intf.startswith("169.254.")

    def wait(self, timeout):
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        self.condition.acquire()
        self.condition.wait(timeout/1000)
        self.condition.release()

    def notifyAll(self):
        """Notifies all waiting threads"""
        self.condition.acquire()
        self.condition.notifyAll()
        self.condition.release()

    def getServiceInfo(self, type, name, timeout=3000):
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type, name)
        if info.request(self, timeout):
            return info
        return None

    def addServiceListener(self, type, listener):
        """Adds a listener for a particular service type.  This object
        will then have its updateRecord method called when information
        arrives for that type."""
        self.removeServiceListener(listener)
        self.browsers.append(ServiceBrowser(self, type, listener))

    def removeServiceListener(self, listener):
        """Removes a listener from the set that is currently listening."""
        for browser in self.browsers:
            if browser.listener == listener:
                browser.cancel()
                del(browser)

    def registerService(self, info, ttl=_DNS_TTL):
        """Registers service information to the network with a default TTL
        of 60 seconds.  Zeroconf will then respond to requests for
        information for that service.  The name of the service may be
        changed if needed to make it unique on the network."""
        self.checkService(info)
        self.services[info.name.lower()] = info
        now = currentTimeMillis()
        nextTime = now
        i = 0
        while i < 3:
            if now < nextTime:
                self.wait(nextTime - now)
                now = currentTimeMillis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            out.addAnswerAtTime(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, ttl, info.name), 0)
            out.addAnswerAtTime(DNSService(info.name, _TYPE_SRV, _CLASS_IN, ttl, info.priority, info.weight, info.port, info.server), 0)
            out.addAnswerAtTime(DNSText(info.name, _TYPE_TXT, _CLASS_IN, ttl, info.text), 0)
            if info.address:
                out.addAnswerAtTime(DNSAddress(info.server, _TYPE_A, _CLASS_IN, ttl, info.address), 0)
            self.send(out)
            i += 1
            nextTime += _REGISTER_TIME

    def unregisterService(self, info):
        """Unregister a service."""
        try:
            del(self.services[info.name.lower()])
        except:
            pass
        now = currentTimeMillis()
        nextTime = now
        i = 0
        while i < 3:
            if now < nextTime:
                self.wait(nextTime - now)
                now = currentTimeMillis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            out.addAnswerAtTime(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
            out.addAnswerAtTime(DNSService(info.name, _TYPE_SRV, _CLASS_IN, 0, info.priority, info.weight, info.port, info.name), 0)
            out.addAnswerAtTime(DNSText(info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)
            if info.address:
                out.addAnswerAtTime(DNSAddress(info.server, _TYPE_A, _CLASS_IN, 0, info.address), 0)
            self.send(out)
            i += 1
            nextTime += _UNREGISTER_TIME

    def unregisterAllServices(self):
        """Unregister all registered services."""
        if len(self.services) > 0:
            now = currentTimeMillis()
            nextTime = now
            i = 0
            while i < 3:
                if now < nextTime:
                    self.wait(nextTime - now)
                    now = currentTimeMillis()
                    continue
                out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                for info in self.services.values():
                    out.addAnswerAtTime(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
                    out.addAnswerAtTime(DNSService(info.name, _TYPE_SRV, _CLASS_IN, 0, info.priority, info.weight, info.port, info.server), 0)
                    out.addAnswerAtTime(DNSText(info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)
                    if info.address:
                        out.addAnswerAtTime(DNSAddress(info.server, _TYPE_A, _CLASS_IN, 0, info.address), 0)
                self.send(out)
                i += 1
                nextTime += _UNREGISTER_TIME

    def checkService(self, info):
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""
        now = currentTimeMillis()
        nextTime = now
        i = 0
        while i < 3:
            for record in self.cache.entriesWithName(info.type):
                if record.type == _TYPE_PTR and not record.isExpired(now) and record.alias == info.name:
                    if (info.name.find('.') < 0):
                        info.name = info.name + ".[" + info.address + ":" + info.port + "]." + info.type
                        self.checkService(info)
                        return
                    raise NonUniqueNameException
            if now < nextTime:
                self.wait(nextTime - now)
                now = currentTimeMillis()
                continue
            out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
            self.debug = out
            out.addQuestion(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN))
            out.addAuthorativeAnswer(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, _DNS_TTL, info.name))
            self.send(out)
            i += 1
            nextTime += _CHECK_TIME

    def addListener(self, listener, question):
        """Adds a listener for a given question.  The listener will have
        its updateRecord method called when information is available to
        answer the question."""
        now = currentTimeMillis()
        self.listeners.append(listener)
        if question is not None:
            for record in self.cache.entriesWithName(question.name):
                if question.answeredBy(record) and not record.isExpired(now):
                    listener.updateRecord(self, now, record)
        self.notifyAll()

    def removeListener(self, listener):
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.notifyAll()
        except:
            pass

    def updateRecord(self, now, rec):
        """Used to notify listeners of new information that has updated
        a record."""
        for listener in self.listeners:
            listener.updateRecord(self, now, rec)
        self.notifyAll()

    def handleResponse(self, msg):
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        now = currentTimeMillis()
        for record in msg.answers:
            expired = record.isExpired(now)
            if record in self.cache.entries():
                if expired:
                    self.cache.remove(record)
                else:
                    entry = self.cache.get(record)
                    if entry is not None:
                        entry.resetTTL(record)
                        record = entry
            else:
                self.cache.add(record)

            self.updateRecord(now, record)

    def handleQuery(self, msg, addr, port):
        """Deal with incoming query packets.  Provides a response if
        possible."""
        out = None

        # Support unicast client responses
        #
        if port != _MDNS_PORT:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, 0)
            for question in msg.questions:
                out.addQuestion(question)
        log.debug( 'Questions...')
        for question in msg.questions:
            log.debug( 'Question: %s', question )
            if question.type == _TYPE_PTR:
                for service in self.services.values():
                    if question.name == service.type:
                        log.info( 'Service query found %s', service.name )
                        if out is None:
                            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                        out.addAnswer(msg, DNSPointer(service.type, _TYPE_PTR, _CLASS_IN, _DNS_TTL, service.name))
                        # devices such as AAstra phones will not re-query to
                        # resolve the pointer, they expect the final IP to show up
                        # in the response
                        out.addAdditionalAnswer(DNSText(service.name, _TYPE_TXT, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.text))
                        out.addAdditionalAnswer(DNSService(service.name, _TYPE_SRV, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.priority, service.weight, service.port, service.server))
                        out.addAdditionalAnswer(DNSAddress(service.server, _TYPE_A, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.address))
            else:
                try:
                    if out is None:
                        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

                    # Answer A record queries for any service addresses we know
                    if question.type == _TYPE_A or question.type == _TYPE_ANY:
                        for service in self.services.values():
                            if service.server == question.name.lower():
                                out.addAnswer(msg, DNSAddress(question.name, _TYPE_A, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.address))


                    service = self.services.get(question.name.lower(), None)
                    if not service: continue

                    if question.type == _TYPE_SRV or question.type == _TYPE_ANY:
                        out.addAnswer(msg, DNSService(question.name, _TYPE_SRV, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.priority, service.weight, service.port, service.server))
                    if question.type == _TYPE_TXT or question.type == _TYPE_ANY:
                        out.addAnswer(msg, DNSText(question.name, _TYPE_TXT, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.text))
                    if question.type == _TYPE_SRV:
                        out.addAdditionalAnswer(DNSAddress(service.server, _TYPE_A, _CLASS_IN | _CLASS_UNIQUE, _DNS_TTL, service.address))
                except Exception, err:
                    log.error(
                        'Error handling query: %s',traceback.format_exc()
                    )

        if out is not None and out.answers:
            out.id = msg.id
            self.send(out, addr, port)
        else:
            log.debug( 'No answer for %s', [q for q in msg.questions] )

    def send(self, out, addr = _MDNS_ADDR, port = _MDNS_PORT):
        """Sends an outgoing packet."""
        # This is a quick test to see if we can parse the packets we generate
        #temp = DNSIncoming(out.packet())
        try:
            packet = out.packet()
            bytes_sent = self.socket.sendto(packet, 0, (addr, port))
        except:
            # Ignore this, it may be a temporary loss of network connection
            pass

    def close(self):
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        if globals()['_GLOBAL_DONE'] == 0:
            globals()['_GLOBAL_DONE'] = 1
            self.notifyAll()
            self.engine.notify()
            self.unregisterAllServices()
            mcastsocket.leave_group( self.socket, _MDNS_ADDR )
            self.socket.close()

