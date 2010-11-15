#! /usr/bin/env python
import logging,socket,sys,os
from Zeroconf import mdns as Zeroconf

# Test a few module features, including service registration, service
# query (for Zoe), and service unregistration.

def main(ip=None):
    print "Multicast DNS Service Discovery for Python, version", Zeroconf.__version__
    r = Zeroconf.Zeroconf(ip or '')
    host_ip = socket.gethostbyname( socket.gethostname())
    try:
        print "1. Testing registration of a service..."
        desc = {'version':'0.10','a':'test value', 'b':'another value'}
        info = Zeroconf.ServiceInfo(
            "_http._tcp.local.", "My Service Name._http._tcp.local.",
            socket.inet_aton(host_ip), 1234, 0, 0, desc
        )
        print "   Registering service..."
        r.registerService(info)
        print "   Registration done."
        print "2. Testing query of service information..."
        print "   Getting ZOE service:", str(r.getServiceInfo("_http._tcp.local.", "ZOE._http._tcp.local."))
        print "   Query done."
        print "3. Testing query of own service..."
        my_service = r.getServiceInfo("_http._tcp.local.", "My Service Name._http._tcp.local.")
        print "   Getting self:", str(my_service)
        print "   Query done."
        print "4. Testing unregister of service information..."
        r.unregisterService(info)
        print "   Unregister done."
    finally:
        r.close()

if __name__ == '__main__':
    logging.basicConfig( level = logging.INFO )
    usage = 'testmdnssd.py [ip.address]'
    sys.exit( main(*sys.argv[1:]) )
