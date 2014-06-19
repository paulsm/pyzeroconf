#! /usr/bin/env python
"""This script simply tests that the multicast setup works on your machine

We create socket that listens on the Zeroconf mDNS port/address and then
join the mDNS multicast group and send a (malformed) message to the group,
our socket should receive that packet (because we have enabled multicast
loopback on the socket).
"""
import socket,os,sys,select,logging
from zeroconf import dns,mcastsocket,mdns

def main(ip):
    """Create a multicast socket, send a message, check it comes back"""
    sock = mcastsocket.create_socket( (ip,dns._MDNS_PORT), loop=True )
    mcastsocket.join_group( sock, dns._MDNS_ADDR )
    try:
        payload = 'hello world'
        for i in range( 5 ):
            sock.sendto( payload, 0, (dns._MDNS_ADDR, dns._MDNS_PORT))
            print 'Waiting for looped message receipt'
            rs,wr,xs = select.select( [sock],[],[], 1.0 )
            data,(addr,port) = sock.recvfrom( 200 )
            if data == payload:
                print 'Success: looped message received from address %s port %s'%(
                    addr,port,
                )
                return 0
        print 'Failure: Looped message not received'
        return 1
    finally:
        mcastsocket.leave_group( sock, dns._MDNS_ADDR )

if __name__ == "__main__":
    logging.basicConfig( level = logging.DEBUG )
    usage = 'testmulticast.py ip.address'
    if not sys.argv[1:]:
        print usage
        sys.exit( 1 )
    sys.exit( main(*sys.argv[1:]) )
