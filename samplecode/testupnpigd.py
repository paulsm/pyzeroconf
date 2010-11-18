#! /usr/bin/env python
"""Trivial script to handle IGD port-opening...
"""
import socket,os,sys,select,logging
from zeroconf import mcastsocket

GROUP = '239.255.255.250'
PORT = 1900

query = """M-SEARCH * HTTP/1.1
HOST: %(ip)s:%(port)s
MAN: ssdp:discover
MX: 10
ST: ssdp:all"""

def handle( sock, data, address ):
    """Handle incoming message about service"""
    print 'received from %s:%s: '%(address,)
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
