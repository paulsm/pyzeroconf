from zeroconf.mdns import *
import socket

class MyListener(object):
    def __init__(self):
        self.r = Zeroconf('')
        pass

    def removeService(self, zeroconf, type_, name):
        print "Service", name, "removed"

    def addService(self, zeroconf, type_, name):
        print "Service", name, "added"
        print "Type is", type_
        info = None
        retries = 0
        while not info and retries < 10:
            info = self.r.getServiceInfo(type_, name)
            if not info:
                print "  (timeout)"
            retries += 1
        print "Address is", str(socket.inet_ntoa(info.getAddress()))
        print "Port is", info.getPort()
        print "Weight is", info.getWeight()
        print "Priority is", info.getPriority()
        print "Server is", info.getServer()
        print "Text is", repr(info.getText())
        print "Properties are", info.getProperties()

if __name__ == '__main__':
    import logging, sys
    logging.basicConfig(level=logging.WARNING)
    print "Multicast DNS Service Discovery for Python Browser test"
    if sys.argv[1:]:
        type_ = sys.argv[1]
    else:
        type_ = "_http._tcp.local."
    r = Zeroconf()
    try:
        print "1. Testing browsing for a service (ctrl-c to stop)..."
        try:
            listener = MyListener()
            browser = ServiceBrowser(r, type_, listener)
            raw_input( 'Press <enter> to exit' )
        except KeyboardInterrupt, err:
            print 'Exiting'
    finally:
        r.close()
