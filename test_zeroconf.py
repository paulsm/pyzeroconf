#!/usr/bin/env python

""" Unit tests for zeroconf.py """

import socket
import struct
import unittest
from threading import Event

from mock import Mock

import zeroconf as r
from zeroconf import (
    byte_ord,
    Listener,
    ServiceBrowser,
    ServiceInfo,
    xrange,
    Zeroconf,
)


class PacketGeneration(unittest.TestCase):

    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, 0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", r._TYPE_SRV,
                                             r._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_match_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        self.assertEqual(len(generated.questions), 1)
        self.assertEqual(len(generated.questions), len(parsed.questions))
        self.assertEqual(question, parsed.questions[0])


class PacketForm(unittest.TestCase):

    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = byte_ord(bytes[0]) << 8 | byte_ord(bytes[1])
        self.assertEqual(id, 0)

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = byte_ord(bytes[2]) << 8 | byte_ord(bytes[3])
        self.assertEqual(flags, 0x0)

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = byte_ord(bytes[2]) << 8 | byte_ord(bytes[3])
        self.assertEqual(flags, 0x8000)

    def test_numbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
         numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 0)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in xrange(10):
            generated.add_question(question)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
         numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 10)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)


class Names(unittest.TestCase):

    def test_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("this.is.a.very.long.name.with.lots.of.parts.in.it.local.",
                                 r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name_part(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_same_name(self):
        name = "paired.local."
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())


class Framework(unittest.TestCase):

    def test_launch_and_close(self):
        rv = r.Zeroconf()
        rv.close()


def test_integration():
    service_added = Event()
    service_removed = Event()

    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_

    class MyListener(object):

        def remove_service(self, zeroconf, type_, name):
            if name == registration_name:
                service_removed.set()

        def add_service(self, zeroconf, type_, name):
            if name == registration_name:
                service_added.set()

    zeroconf_browser = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf_browser, type_, listener)

    zeroconf_registrar = Zeroconf()
    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name,
        socket.inet_aton("10.0.1.2"), 80, 0, 0,
        desc, "ash-2.local.")
    zeroconf_registrar.register_service(info)

    try:
        service_added.wait(1)
        assert service_added.is_set()
        zeroconf_registrar.unregister_service(info)
        service_removed.wait(1)
        assert service_removed.is_set()
    finally:
        zeroconf_registrar.close()
        browser.cancel()
        zeroconf_browser.close()


def test_listener_handles_closed_socket_situation_gracefully():
    error = socket.error(socket.EBADF)
    error.errno = socket.EBADF

    zeroconf = Mock()
    zeroconf.socket.recvfrom.side_effect = error

    listener = Listener(zeroconf)
    listener.handle_read()
