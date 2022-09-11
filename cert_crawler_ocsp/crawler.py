import socket
import sys

sys.path.insert(0, 'lib')
from validity import *

sys.path.insert(0, 'src/lib')
import base64
import pprint
import os
import ssl


def getCertificateListsThroughLuminati2():
    site = "ec2-52-70-160-126.compute-1.amazonaws.com"
    auth = 'lum-customer-mmlab-zone-expcert-dns-remote:ea3099501e1b'

    headers = {}
    headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')
    headers['Connection'] = 'Close'
    CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % (site, 443)
    CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket.setdefaulttimeout(3)
    s.connect(('107.170.34.184', 22225))
    s.send(bytes(CONNECT, "utf-8"))
    resp = s.recv(4096)
    print(resp)

    s.send(bytes("connection: close\r\n", "utf-8"))
    resp = s.recv(4096)
    print(resp)
    """

    CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % ('ec2-52-70-160-126.compute-1.amazonaws.com', 443)
    CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'
    s.send(bytes(CONNECT, "utf-8"))
    resp = s.recv(4096)
    print (resp)
    """
    # s.connect( (site, 443 ))

    context = ssl.create_default_context()
    context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE
    context.verify_mode = ssl.CERT_REQUIRED

    s = context.wrap_socket(s, server_hostname=site)

    # certs = [s.getpeercert(binary_form=True)]#, validate=False)
    certs = s.getpeercertchain(binary_form=True, validate=False)

    return certs


def getCertificateListsThroughLuminati(site):
    CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % (site, 443)
    auth = 'lum-customer-mmlab-zone-expcert-dns-remote-country-fi-session-111:ea3099501e1b'

    headers = {}
    headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')
    headers['Connection'] = 'Close'
    CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket.setdefaulttimeout(3)
    s.connect(('140.82.4.161', 22225))
    s.send(bytes(CONNECT, "utf-8"))
    resp = s.recv(4096)
    print(resp)

    # s.connect( (site, 443 ))

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # context.verify_mode = ssl.CERT_REQUIRED

    s = context.wrap_socket(s, server_hostname=site)

    # certs = [s.getpeercert(binary_form=True)]#, validate=False)
    certs = s.getpeercertchain(binary_form=True, validate=False)
    w = open("/tmp/cert", "w")
    for cert in certs:
        sa = base64.b64encode(cert).decode("utf-8")
        print(sa)
        c = Certificate(sa)
        # w.write("%s,%s\n" % (certs.index(cert), sa))
    w.close()

    # print (len(certs))
    return certs


def getCertificateLists(site):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # socket.setdefaulttimeout(3)

    # context = ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    s = context.wrap_socket(s, server_hostname=site)  # , ssl_version=ssl.PROTOCOL_SSLv23)
    s.connect((site, 443))

    # certs = [s.getpeercert(binary_form=True)]#, validate=False)
    certs = s.getpeercertchain(binary_form=True, validate=False)
    w = open("/tmp/cert", "w")
    for cert in certs:
        sa = base64.b64encode(cert).decode("utf-8")
        print(sa)
        # c = Certificate(sa)
        w.write("%s,%s\n" % (certs.index(cert), sa))
    w.close()

    return certs


def saveCerts(site, directory, certs):
    PATH = "/home/tjchung/research/luminati/cert_crawl/certs/answer/%s" % directory
    PATH = "/home/tjchung/research/luminati/cert_crawl/certs/answer/%s" % directory

    for cert in certs:
        fname = "%s_%s.der" % (site, certs.index(cert))
        w = open(os.path.join(PATH, fname), "wb")
        w.write(cert)
        w.close()


sites = ["expired.badssl.com", \
         "wrong.host.badssl.com", \
         "self-signed.badssl.com"]

'''
context = ssl.create_default_context()
conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname="www.badssl.com")
conn.connect(("expired.badssl.com", 443))
cert = conn.getpeercert()
pprint.pprint(cert)
'''

print(getCertificateLists('twin-cities.umn.edu'))
# print (getCertificateLists('66.151.183.77'))
# print (checkValidity (getCertificateListsThroughLuminati('twin-cities.umn.edu')))
# getCertificateLists('www.mol.fi')
# print (checkValidity (getCertificateListsThroughLuminati('www.mol.fi')))
# print (checkValidity (getCertificateLists('www.usc.edu')))
# print (checkValidity (getCertificateLists('www.usc.edu')))
# print (checkValidity (getCertificateListsThroughLuminati2()))
# site = "ec2-52-70-160-126.compute-1.amazonaws.com"
# print (checkValidity((getCertificateLists(site))))
# print (checkValidity((getCertificateLists('self-signed.badssl.com'))))
# site = "revoked.scotthelme.co.uk"
# certs = getCertificateListsThroughLuminati(site)

"""
sys.exit(1)
for site in sites[:1]:
    #certs = getCertificateListsThroughLuminati(site)
    #pprint.pprint(certs[0]])
    #saveCerts(site, "badssl", certs)

    w = open("/tmp/tmp.der", "w")
    for cert in certs:
        #fname = "tmp.der" % (site, certs.index(cert))
        w.write("%s,%s,%s\n" % ( site, certs.index(cert), base64.b64encode(cert).decode("utf-8")))
    w.close()
"""
