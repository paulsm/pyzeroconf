"""Multicast socket setup code

This is refactored from the Zeroconf.py main module to allow for reuse within
multiple environments (e.g. multicast SIP configuration, multicast paging
groups and the like).
"""
import socket,logging
log = logging.getLogger( __name__ )

def create_socket( address, TTL=1, loop=True, reuse=True ):
    """Create our multicast socket for mDNS usage

    Creates a multicast UDP socket with multicast address configured for the
    ip in address[0], and bound on all interfaces with port address[1].
    Configures TTL and loop-back operation

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, TTL)
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, int(bool(loop)))
    if reuse:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            # SO_REUSEADDR should be equivalent to SO_REUSEPORT for
            # multicast UDP sockets (p 731, "TCP/IP Illustrated,
            # Volume 2"), but some BSD-derived systems require
            # SO_REUSEPORT to be specified explicity.  Also, not all
            # versions of Python have SO_REUSEPORT available.  So
            # if you're on a BSD-based system, and haven't upgraded
            # to Python 2.3 yet, you may find this library doesn't
            # work as expected.
            #
            pass
    try:
        # Note: multicast is *not* working if we don't bind on all interfaces, most likely
        # because the 224.* isn't getting mapped to the address of the interface...
        sock.bind(('',address[1]))
    except Exception, err:
        # Some versions of linux raise an exception even though
        # the SO_REUSE* options have been set, so ignore it
        #
        log.error('Failure binding: %s', err)
    if address[0]:
        # listen/send on a single interface...
        interface_ip = address[0]
        log.debug( 'Setting multicast to use interface of %s', address[0] )
        sock.setsockopt(
            socket.SOL_IP, socket.IP_MULTICAST_IF,
            socket.inet_aton( interface_ip) +
                socket.inet_aton('0.0.0.0')
        )
    return sock

def join_group( sock, group ):
    """Add our socket to this multicast group"""
    log.info( 'Joining multicast group: %s', group )
    sock.setsockopt(
        socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(group) + socket.inet_aton('0.0.0.0')
    )
def leave_group( sock, group ):
    """Remove our socket from this multicast group"""
    log.info( 'Leaving multicast group: %s', group )
    sock.setsockopt(
        socket.SOL_IP, socket.IP_DROP_MEMBERSHIP,
        socket.inet_aton(group) + socket.inet_aton('0.0.0.0')
    )
