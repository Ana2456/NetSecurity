# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
This example demonstrates how to run a reverse proxy.

Run this example with:
    $ python reverse-proxy.py

Then visit http://localhost:8080/ in your web browser.
"""

from twisted.internet import reactor
from twisted.web import  server
import reverse_proxy

site = server.Site(reverse_proxy.ReverseProxyResource('weevil.info', 80, b''))
reactor.listenTCP(8080, site)
reactor.run()