#! /usr/bin/env python
from zeroconf import mdns, mcastsocket, dns

def main():
    z = mdns.Zeroconf( '0.0.0.0' )
    try:
        print z.probeName( 'coolserver.local.' )
    finally:
        z.close()

if __name__ == "__main__":
    import logging
    logging.basicConfig( 
        #level = logging.DEBUG 
    )
    main()
