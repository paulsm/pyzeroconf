#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

import logging
import socket
import sys

from zeroconf import __version__, ServiceInfo, Zeroconf

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    # Test a few module features, including service registration, service
    # query (for Zoe), and service unregistration.
    print("Multicast DNS Service Discovery for Python, version %s" % (__version__,))
    r = Zeroconf()
    print("1. Testing registration of a service...")
    desc = {'version': '0.10', 'a': 'test value', 'b': 'another value'}
    info = ServiceInfo("_http._tcp.local.",
                       "My Service Name._http._tcp.local.",
                       socket.inet_aton("127.0.0.1"), 1234, 0, 0, desc)
    print("   Registering service...")
    r.register_service(info)
    print("   Registration done.")
    print("2. Testing query of service information...")
    print("   Getting ZOE service: %s" % (
        r.get_service_info("_http._tcp.local.", "ZOE._http._tcp.local.")))
    print("   Query done.")
    print("3. Testing query of own service...")
    info = r.get_service_info("_http._tcp.local.", "My Service Name._http._tcp.local.")
    assert info
    print("   Getting self: %s" % (info,))
    print("   Query done.")
    print("4. Testing unregister of service information...")
    r.unregister_service(info)
    print("   Unregister done.")
    r.close()
