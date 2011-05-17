#! /usr/bin/env python
"""Trivial script to handle IGD port-opening...
"""
import socket,os,sys,select,logging
from zeroconf import mcastsocket
try:
    from lxml import etree
except ImportError:
    try:
        # Python 2.5
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
          # Python 2.5
            import xml.etree.ElementTree as etree
        except ImportError:
            try:
                # normal cElementTree install
                import cElementTree as etree
            except ImportError:
                import elementtree.ElementTree as etree

GROUP = '239.255.255.250'
PORT = 1900

query = """M-SEARCH * HTTP/1.1
HOST: %(ip)s:%(port)s
MAN: ssdp:discover
MX: 10
ST: ssdp:all"""
query = """M-SEARCH * HTTP/1.1
HOST: %(ip)s:%(port)s
MAN: ssdp:discover
MX: 10
ST: upnp:rootdevice"""

def describe_device( record, indent = '' ):
    print 'Found: ', record.find( 'friendlyName' ).text
    for service in record.find( 'serviceList' ):
        print indent, 'Service:', service.find( 'serviceType' ).text
    if record.find( 'deviceList' ):
        for device in record.find( 'deviceList' ):
            describe_device( device, indent + '  ' )


def parse( result ):
    root = etree.fromstring( result )
    describe_device(  root.find( 'device' ) )

def handle( sock, data, address ):
    """Handle incoming message about service"""
    print 'received from %s: '%(address,)
    print data

# :schemas-upnp-org:device:InternetGatewayDevice:1

def main(ip):
    """Create a multicast socket, send a message, check it comes back"""
    port = PORT
    sock = mcastsocket.create_socket( (ip,port), loop=False )
    mcastsocket.join_group( sock, GROUP )
    try:
        payload = query % locals()
        while True:
            sock.sendto( payload, 0, (GROUP,PORT))
            print 'Waiting for responses'
            rs,wr,xs = select.select( [sock],[],[], 20.0 )
            if rs:
                data, addr = sock.recvfrom( 2000 )
                handle( sock, data, addr )
        return 1
    finally:
        mcastsocket.leave_group( sock, GROUP )

if __name__ == "__main__":
    logging.basicConfig( level = logging.DEBUG )
    usage = 'testupnpigd.py ip.address'
    if not sys.argv[1:]:
        print usage
        sys.exit( 1 )
    sys.exit( main(*sys.argv[1:]) )
