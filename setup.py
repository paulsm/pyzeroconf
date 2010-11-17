#! /usr/bin/env python
"""Install Zeroconf.py using distutils"""
from distutils.core import setup
import os
info = {}
keys = [('__author__','author'),('__email__','author_email'),('__version__','version')]
for line in open( os.path.join('zeroconf','__init__.py') ):
    for key,inf in keys:
        if line.startswith( key ):
            info[inf] = line.strip().split('=')[1].strip().strip('"').strip("'")
            keys.remove( (key,inf))
            if not keys:
                break
if __name__ == "__main__":
    setup(
        name='pyzeroconf',
        description='Python Zeroconf (mDNS) Library',
        url='http://digitaltorque.ca',
        packages=['zeroconf'],
        #scripts=['Browser.py'],
        classifiers=[
            'Development Status :: Production',
            'License :: OSI Approved :: LGPL2',
            'Topic :: Networking',
            'Intended Audience :: Developers',
            'Operating System :: Any',
            'Environment :: Console',
        ],
        **info
    )
