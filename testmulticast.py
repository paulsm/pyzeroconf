#! /usr/bin/env python
"""This script simply tests that the Zeroconf multicast setup works on your machine"""
import Zeroconf,socket,os,sys,select,logging

def main(ip):
    """Create a multicast socket, send a message, check it comes back"""
    sock = Zeroconf.Zeroconf.create_socket( (ip,Zeroconf._MDNS_PORT) )
    payload = 'hello world'
    for i in range( 5 ):
        sock.sendto( payload, 0, (Zeroconf._MDNS_ADDR, Zeroconf._MDNS_PORT))
        print 'Waiting for looped message receipt'
        rs,wr,xs = select.select( [sock],[],[], 1.0 )
        data,(addr,port) = sock.recvfrom( 200 )
        if data == payload:
            print 'Success: looped message received' 
            return 0
    print 'Failure: Looped message not received'
    return 1

if __name__ == "__main__":
    logging.basicConfig( level = logging.DEBUG )
    usage = 'testmulticast.py ip.address'
    if not sys.argv[1:]:
        print usage 
        sys.exit( 1 )
    sys.exit( main(*sys.argv[1:]) )
