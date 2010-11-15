""" Multicast DNS Service Discovery for Python, v0.12
    Copyright (C) 2003, Paul Scott-Murphy

    This module provides a DNS/mDNS encoding/decoding facility which
    is used by the package to communicate with mDNS servers/clients.

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
import string
import time
import struct
import socket
import traceback
import logging
log = logging.getLogger(__name__)
__all__ = [
    'ServiceInfo',
    'DNSAddress', 'DNSCache', 'DNSEntry', 'DNSHinfo', 'DNSIncoming',
    'DNSOutgoing', 'DNSPointer', 'DNSQuestion', 'DNSRecord', 'DNSService',
    'DNSText',
    'AbstractMethodException', 'BadTypeInNameException',
    'NamePartTooLongException', 'NonLocalNameException', 'NonUniqueNameException',
    'currentTimeMillis',
]

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

# implementation classes

class DNSEntry(object):
    """A DNS entry"""

    def __init__(self, name, type, clazz):
        self.key = string.lower(name)
        self.name = name
        self.type = type
        self.clazz = clazz & _CLASS_MASK
        self.unique = (clazz & _CLASS_UNIQUE) != 0

    def __eq__(self, other):
        """Equality test on name, type, and class"""
        if isinstance(other, DNSEntry):
            return self.name == other.name and self.type == other.type and self.clazz == other.clazz
        return 0

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def getClazz(self, clazz):
        """Class accessor"""
        try:
            return _CLASSES[clazz]
        except:
            return "?(%s)" % (clazz)

    def getType(self, type):
        """Type accessor"""
        try:
            return _TYPES[type]
        except:
            return "?(%s)" % (type)

    def toString(self, hdr, other):
        """String representation with additional information"""
        result = "%s[%s,%s" % (hdr, self.getType(self.type), self.getClazz(self.clazz))
        if self.unique:
            result += "-unique,"
        else:
            result += ","
        result += self.name
        if other is not None:
            result += ",%s]" % (other)
        else:
            result += "]"
        return result

class DNSQuestion(DNSEntry):
    """A DNS question entry"""

    def __init__(self, name, type, clazz):
        if not name.endswith(".local."):
            raise NonLocalNameException
        DNSEntry.__init__(self, name, type, clazz)

    def answeredBy(self, rec):
        """Returns true if the question is answered by the record"""
        return self.clazz == rec.clazz and (self.type == rec.type or self.type == _TYPE_ANY) and self.name == rec.name

    def __repr__(self):
        """String representation"""
        return DNSEntry.toString(self, "question", None)
    __str__ = __repr__

class DNSRecord(DNSEntry):
    """A DNS record - like a DNS entry, but has a TTL"""

    def __init__(self, name, type, clazz, ttl):
        DNSEntry.__init__(self, name, type, clazz)
        self.ttl = ttl
        self.created = currentTimeMillis()

    def __eq__(self, other):
        """Tests equality as per DNSRecord"""
        if isinstance(other, DNSRecord):
            return DNSEntry.__eq__(self, other)
        return 0

    def suppressedBy(self, msg):
        """Returns true if any answer in a message can suffice for the
        information held in this record."""
        for record in msg.answers:
            if self.suppressedByAnswer(record):
                return 1
        return 0

    def suppressedByAnswer(self, other):
        """Returns true if another record has same name, type and class,
        and if its TTL is at least half of this record's."""
        if self == other and other.ttl > (self.ttl / 2):
            return 1
        return 0

    def getExpirationTime(self, percent):
        """Returns the time at which this record will have expired
        by a certain percentage."""
        return self.created + (percent * self.ttl * 10)

    def getRemainingTTL(self, now):
        """Returns the remaining TTL in seconds."""
        return max(0, (self.getExpirationTime(100) - now) / 1000)

    def isExpired(self, now):
        """Returns true if this record has expired."""
        return self.getExpirationTime(100) <= now

    def isStale(self, now):
        """Returns true if this record is at least half way expired."""
        return self.getExpirationTime(50) <= now

    def resetTTL(self, other):
        """Sets this record's TTL and created time to that of
        another record."""
        self.created = other.created
        self.ttl = other.ttl

    def write(self, out):
        """Abstract method"""
        raise AbstractMethodException

    def toString(self, other):
        """String representation with addtional information"""
        arg = "%s/%s,%s" % (self.ttl, self.getRemainingTTL(currentTimeMillis()), other)
        return DNSEntry.toString(self, "record", arg)

class DNSAddress(DNSRecord):
    """A DNS address record"""

    def __init__(self, name, type, clazz, ttl, address):
        DNSRecord.__init__(self, name, type, clazz, ttl)
        self.address = address

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.writeString(self.address, len(self.address))

    def __eq__(self, other):
        """Tests equality on address"""
        if isinstance(other, DNSAddress):
            return self.address == other.address
        return 0

    def __repr__(self):
        """String representation"""
        try:
            return socket.inet_ntoa(self.address)
        except:
            return self.address

class DNSHinfo(DNSRecord):
    """A DNS host information record"""

    def __init__(self, name, type, clazz, ttl, cpu, os):
        DNSRecord.__init__(self, name, type, clazz, ttl)
        self.cpu = cpu
        self.os = os

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.writeString(self.cpu, len(self.cpu))
        out.writeString(self.os, len(self.os))

    def __eq__(self, other):
        """Tests equality on cpu and os"""
        if isinstance(other, DNSHinfo):
            return self.cpu == other.cpu and self.os == other.os
        return 0

    def __repr__(self):
        """String representation"""
        return self.cpu + " " + self.os

class DNSPointer(DNSRecord):
    """A DNS pointer record"""

    def __init__(self, name, type, clazz, ttl, alias):
        DNSRecord.__init__(self, name, type, clazz, ttl)
        self.alias = alias

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.writeName(self.alias)

    def __eq__(self, other):
        """Tests equality on alias"""
        if isinstance(other, DNSPointer):
            return self.alias == other.alias
        return 0

    def __repr__(self):
        """String representation"""
        return self.toString(self.alias)

class DNSText(DNSRecord):
    """A DNS text record"""

    def __init__(self, name, type, clazz, ttl, text):
        DNSRecord.__init__(self, name, type, clazz, ttl)
        self.text = text

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.writeString(self.text, len(self.text))

    def __eq__(self, other):
        """Tests equality on text"""
        if isinstance(other, DNSText):
            return self.text == other.text
        return 0

    def __repr__(self):
        """String representation"""
        if len(self.text) > 10:
            return self.toString(self.text[:7] + "...")
        else:
            return self.toString(self.text)

class DNSService(DNSRecord):
    """A DNS service record"""

    def __init__(self, name, type, clazz, ttl, priority, weight, port, server):
        DNSRecord.__init__(self, name, type, clazz, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.writeShort(self.priority)
        out.writeShort(self.weight)
        out.writeShort(self.port)
        out.writeName(self.server)

    def __eq__(self, other):
        """Tests equality on priority, weight, port and server"""
        if isinstance(other, DNSService):
            return self.priority == other.priority and self.weight == other.weight and self.port == other.port and self.server == other.server
        return 0

    def __repr__(self):
        """String representation"""
        return self.toString("%s:%s" % (self.server, self.port))

class DNSIncoming(object):
    """Object representation of an incoming DNS packet"""

    def __init__(self, data):
        """Constructor from string holding bytes of packet"""
        self.offset = 0
        self.data = data
        self.questions = []
        self.answers = []
        self.numQuestions = 0
        self.numAnswers = 0
        self.numAuthorities = 0
        self.numAdditionals = 0

        self.readHeader()
        self.readQuestions()
        self.readOthers()

    def readHeader(self):
        """Reads header portion of packet"""
        format = '!HHHHHH'
        length = struct.calcsize(format)
        info = struct.unpack(format, self.data[self.offset:self.offset+length])
        self.offset += length

        self.id = info[0]
        self.flags = info[1]
        self.numQuestions = info[2]
        self.numAnswers = info[3]
        self.numAuthorities = info[4]
        self.numAdditionals = info[5]

    def readQuestions(self):
        """Reads questions section of packet"""
        format = '!HH'
        length = struct.calcsize(format)
        for i in range(0, self.numQuestions):
            name = self.readName()
            info = struct.unpack(format, self.data[self.offset:self.offset+length])
            self.offset += length

            question = DNSQuestion(name, info[0], info[1])
            self.questions.append(question)

    def readInt(self):
        """Reads an integer from the packet"""
        format = '!I'
        length = struct.calcsize(format)
        info = struct.unpack(format, self.data[self.offset:self.offset+length])
        self.offset += length
        return info[0]

    def readCharacterString(self):
        """Reads a character string from the packet"""
        length = ord(self.data[self.offset])
        self.offset += 1
        return self.readString(length)

    def readString(self, len):
        """Reads a string of a given length from the packet"""
        format = '!' + str(len) + 's'
        length =  struct.calcsize(format)
        info = struct.unpack(format, self.data[self.offset:self.offset+length])
        self.offset += length
        return info[0]

    def readUnsignedShort(self):
        """Reads an unsigned short from the packet"""
        format = '!H'
        length = struct.calcsize(format)
        info = struct.unpack(format, self.data[self.offset:self.offset+length])
        self.offset += length
        return info[0]

    def readOthers(self):
        """Reads the answers, authorities and additionals section of the packet"""
        format = '!HHiH'
        length = struct.calcsize(format)
        n = self.numAnswers + self.numAuthorities + self.numAdditionals
        for i in range(0, n):
            domain = self.readName()
            info = struct.unpack(format, self.data[self.offset:self.offset+length])
            self.offset += length

            try:
                rec = None
                if info[0] == _TYPE_A:
                    rec = DNSAddress(domain, info[0], info[1], info[2], self.readString(4))
                elif info[0] == _TYPE_CNAME or info[0] == _TYPE_PTR:
                    rec = DNSPointer(domain, info[0], info[1], info[2], self.readName())
                elif info[0] == _TYPE_TXT:
                    rec = DNSText(domain, info[0], info[1], info[2], self.readString(info[3]))
                elif info[0] == _TYPE_SRV:
                    rec = DNSService(domain, info[0], info[1], info[2], self.readUnsignedShort(), self.readUnsignedShort(), self.readUnsignedShort(), self.readName())
                elif info[0] == _TYPE_HINFO:
                    rec = DNSHinfo(domain, info[0], info[1], info[2], self.readCharacterString(), self.readCharacterString())
                elif info[0] == _TYPE_AAAA:
                    rec = DNSAddress(domain, info[0], info[1], info[2], self.readString(16))
                else:
                    # Try to ignore types we don't know about
                    # this may mean the rest of the name is
                    # unable to be parsed, and may show errors
                    # so this is left for debugging.  New types
                    # encountered need to be parsed properly.
                    #
                    log.warn(
                        "Unknown DNS query type: %s", info[0]
                    )

                if rec is not None:
                    self.answers.append(rec)
            except Exception, err:
                log.warn( "Failure on record type %s, ignoring: %s", info[0], err )

    def isQuery(self):
        """Returns true if this is a query"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def isResponse(self):
        """Returns true if this is a response"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    def readUTF(self, offset, len):
        """Reads a UTF-8 string of a given length from the packet

        TODO: there are cases were non-utf-8 data comes through,
        we need to decide how to properly handle these.
        """
        return self.data[offset:offset+len].decode('utf-8','ignore')

    def readName(self):
        """Reads a domain name from the packet"""
        result = ''
        off = self.offset
        next = -1
        first = off

        while 1:
            len = ord(self.data[off])
            off += 1
            if len == 0:
                break
            t = len & 0xC0
            if t == 0x00:
                result = ''.join((result, self.readUTF(off, len) + '.'))
                off += len
            elif t == 0xC0:
                if next < 0:
                    next = off + 1
                off = ((len & 0x3F) << 8) | ord(self.data[off])
                if off >= first:
                    raise "Bad domain name (circular) at " + str(off)
                first = off
            else:
                raise "Bad domain name at " + str(off)

        if next >= 0:
            self.offset = next
        else:
            self.offset = off

        return result


class DNSOutgoing(object):
    """Object representation of an outgoing packet"""

    def __init__(self, flags, multicast = 1):
        self.finished = 0
        self.id = 0
        self.multicast = multicast
        self.flags = flags
        self.names = {}
        self.data = []
        self.size = 12

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def addQuestion(self, record):
        """Adds a question"""
        self.questions.append(record)

    def addAnswer(self, inp, record):
        """Adds an answer"""
        if not record.suppressedBy(inp):
            self.addAnswerAtTime(record, 0)

    def addAnswerAtTime(self, record, now):
        """Adds an answer if if does not expire by a certain time"""
        if record is not None:
            if now == 0 or not record.isExpired(now):
                self.answers.append((record, now))

    def addAuthorativeAnswer(self, record):
        """Adds an authoritative answer"""
        self.authorities.append(record)

    def addAdditionalAnswer(self, record):
        """Adds an additional answer"""
        self.additionals.append(record)

    def writeByte(self, value):
        """Writes a single byte to the packet"""
        format = '!c'
        self.data.append(struct.pack(format, chr(value)))
        self.size += 1

    def insertShort(self, index, value):
        """Inserts an unsigned short in a certain position in the packet"""
        format = '!H'
        self.data.insert(index, struct.pack(format, value))
        self.size += 2

    def writeShort(self, value):
        """Writes an unsigned short to the packet"""
        format = '!H'
        self.data.append(struct.pack(format, value))
        self.size += 2

    def writeInt(self, value):
        """Writes an unsigned integer to the packet"""
        format = '!I'
        self.data.append(struct.pack(format, long(value)))
        self.size += 4

    def writeString(self, value, length):
        """Writes a string to the packet"""
        format = '!' + str(length) + 's'
        self.data.append(struct.pack(format, value))
        self.size += length

    def writeUTF(self, s):
        """Writes a UTF-8 string of a given length to the packet"""
        utfstr = s.encode('utf-8')
        length = len(utfstr)
        if length > 64:
            raise NamePartTooLongException
        self.writeByte(length)
        self.writeString(utfstr, length)

    def writeName(self, name):
        """Writes a domain name to the packet"""

        try:
            # Find existing instance of this name in packet
            #
            index = self.names[name]
        except KeyError:
            # No record of this name already, so write it
            # out as normal, recording the location of the name
            # for future pointers to it.
            #
            self.names[name] = self.size
            parts = name.split('.')
            if parts[-1] == '':
                parts = parts[:-1]
            for part in parts:
                self.writeUTF(part)
            self.writeByte(0)
            return

        # An index was found, so write a pointer to it
        #
        self.writeByte((index >> 8) | 0xC0)
        self.writeByte(index)

    def writeQuestion(self, question):
        """Writes a question to the packet"""
        self.writeName(question.name)
        self.writeShort(question.type)
        self.writeShort(question.clazz)

    def writeRecord(self, record, now):
        """Writes a record (answer, authoritative answer, additional) to
        the packet"""
        self.writeName(record.name)
        self.writeShort(record.type)
        if record.unique and self.multicast:
            self.writeShort(record.clazz | _CLASS_UNIQUE)
        else:
            self.writeShort(record.clazz)
        if now == 0:
            self.writeInt(record.ttl)
        else:
            self.writeInt(record.getRemainingTTL(now))
        index = len(self.data)
        # Adjust size for the short we will write before this record
        #
        self.size += 2
        record.write(self)
        self.size -= 2

        length = len(''.join(self.data[index:]))
        self.insertShort(index, length) # Here is the short we adjusted for

    def packet(self):
        """Returns a string containing the packet's bytes

        No further parts should be added to the packet once this
        is done."""
        if not self.finished:
            self.finished = 1
            for question in self.questions:
                self.writeQuestion(question)
            for answer, time in self.answers:
                self.writeRecord(answer, time)
            for authority in self.authorities:
                self.writeRecord(authority, 0)
            for additional in self.additionals:
                self.writeRecord(additional, 0)

            self.insertShort(0, len(self.additionals))
            self.insertShort(0, len(self.authorities))
            self.insertShort(0, len(self.answers))
            self.insertShort(0, len(self.questions))
            self.insertShort(0, self.flags)
            if self.multicast:
                self.insertShort(0, 0)
            else:
                self.insertShort(0, self.id)
        return ''.join(self.data)


class DNSCache(object):
    """A cache of DNS entries"""

    def __init__(self):
        self.cache = {}

    def add(self, entry):
        """Adds an entry"""
        try:
            list = self.cache[entry.key]
        except:
            list = self.cache[entry.key] = []
        list.append(entry)

    def remove(self, entry):
        """Removes an entry"""
        try:
            list = self.cache[entry.key]
            list.remove(entry)
        except:
            pass

    def get(self, entry):
        """Gets an entry by key.  Will return None if there is no
        matching entry."""
        try:
            list = self.cache[entry.key]
            return list[list.index(entry)]
        except:
            return None

    def getByDetails(self, name, type, clazz):
        """Gets an entry by details.  Will return None if there is
        no matching entry."""
        entry = DNSEntry(name, type, clazz)
        return self.get(entry)

    def entriesWithName(self, name):
        """Returns a list of entries whose key matches the name."""
        try:
            return self.cache[name]
        except:
            return []

    def entries(self):
        """Returns a list of all entries"""
        def add(x, y): return x+y
        try:
            return reduce(add, self.cache.values())
        except:
            return []

class ServiceInfo(object):
    """Service information"""

    def __init__(self, type, name, address=None, port=None, weight=0, priority=0, properties=None, server=None):
        """Create a service description.

        type: fully qualified service type name
        name: fully qualified service name
        address: IP address as unsigned short, network byte order
        port: port that the service runs on
        weight: weight of the service
        priority: priority of the service
        properties: dictionary of properties (or a string holding the bytes for the text field)
        server: fully qualified name for service host (defaults to name)"""

        if not name.endswith(type):
            raise BadTypeInNameException
        self.type = type
        self.name = name
        self.address = address
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name #'.'.join([x for x in name.split('.') if not x.startswith('_')])
        self.setProperties(properties)

    def setProperties(self, properties):
        """Sets properties and text of this info from a dictionary"""
        if isinstance(properties, dict):
            self.properties = properties
            list = []
            result = ''
            for key in properties:
                value = properties[key]
                if value is None:
                    suffix = ''.encode('utf-8')
                elif isinstance(value, str):
                    suffix = value.encode('utf-8')
                elif isinstance(value, int):
                    if value:
                        suffix = 'true'
                    else:
                        suffix = 'false'
                else:
                    suffix = ''.encode('utf-8')
                list.append('='.join((key, suffix)))
            for item in list:
                result = ''.join((result, struct.pack('!c', chr(len(item))), item))
            self.text = result
        else:
            self.text = properties

    def setText(self, text):
        """Sets properties and text given a text field"""
        self.text = text
        try:
            result = {}
            end = len(text)
            index = 0
            strs = []
            while index < end:
                length = ord(text[index])
                index += 1
                strs.append(text[index:index+length])
                index += length

            for s in strs:
                eindex = s.find('=')
                if eindex == -1:
                    # No equals sign at all
                    key = s
                    value = 0
                else:
                    key = s[:eindex]
                    value = s[eindex+1:]
                    if value == 'true':
                        value = 1
                    elif value == 'false' or not value:
                        value = 0

                # Only update non-existent properties
                if key and result.get(key) == None:
                    result[key] = value

            self.properties = result
        except Exception, err:
            log.error( "Failure composing text: %s", traceback.format_exc() )
            self.properties = None

    def getType(self):
        """Type accessor"""
        return self.type

    def getName(self):
        """Name accessor"""
        if self.type is not None and self.name.endswith("." + self.type):
            return self.name[:len(self.name) - len(self.type) - 1]
        return self.name

    def getAddress(self):
        """Address accessor"""
        return self.address

    def getPort(self):
        """Port accessor"""
        return self.port

    def getPriority(self):
        """Pirority accessor"""
        return self.priority

    def getWeight(self):
        """Weight accessor"""
        return self.weight

    def getProperties(self):
        """Properties accessor"""
        return self.properties

    def getText(self):
        """Text accessor"""
        return self.text

    def getServer(self):
        """Server accessor"""
        return self.server

    def updateRecord(self, zeroconf, now, record):
        """Updates service information from a DNS record"""
        if record is not None and not record.isExpired(now):
            if record.type == _TYPE_A:
                if record.name == self.name:
                    self.address = record.address
            elif record.type == _TYPE_SRV:
                if record.name == self.name:
                    self.server = record.server
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    self.address = None
                    self.updateRecord(zeroconf, now, zeroconf.cache.getByDetails(self.server, _TYPE_A, _CLASS_IN))
            elif record.type == _TYPE_TXT:
                if record.name == self.name:
                    self.setText(record.text)

    def request(self, zeroconf, timeout):
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        now = currentTimeMillis()
        delay = _LISTENER_TIME
        next = now + delay
        last = now + timeout
        result = 0
        try:
            zeroconf.addListener(self, DNSQuestion(self.name, _TYPE_ANY, _CLASS_IN))
            while self.server is None or self.address is None or self.text is None:
                if last <= now:
                    return 0
                if next <= now:
                    out = DNSOutgoing(_FLAGS_QR_QUERY)
                    out.addQuestion(DNSQuestion(self.name, _TYPE_SRV, _CLASS_IN))
                    out.addAnswerAtTime(zeroconf.cache.getByDetails(self.name, _TYPE_SRV, _CLASS_IN), now)
                    out.addQuestion(DNSQuestion(self.name, _TYPE_TXT, _CLASS_IN))
                    out.addAnswerAtTime(zeroconf.cache.getByDetails(self.name, _TYPE_TXT, _CLASS_IN), now)
                    if self.server is not None:
                        out.addQuestion(DNSQuestion(self.server, _TYPE_A, _CLASS_IN))
                        out.addAnswerAtTime(zeroconf.cache.getByDetails(self.server, _TYPE_A, _CLASS_IN), now)
                    zeroconf.send(out)
                    next = now + delay
                    delay = delay * 2

                zeroconf.wait(min(next, last) - now)
                now = currentTimeMillis()
            result = 1
        finally:
            zeroconf.removeListener(self)

        return result

    def __eq__(self, other):
        """Tests equality of service name"""
        if isinstance(other, ServiceInfo):
            return other.name == self.name
        return 0

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        result = "service[%s,%s:%s," % (self.name, socket.inet_ntoa(self.getAddress()), self.port)
        if self.text is None:
            result += "None"
        else:
            if len(self.text) < 20:
                result += self.text
            else:
                result += self.text[:17] + "..."
        result += "]"
        return result

