import socket
import sys

sys.path.insert(0, 'lib')

sys.path.insert(0, 'src/lib')
import base64
import pprint
import os
import ssl
import ssl
from cryptography import x509


def getCertificate():
    global cid_set

    CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % ('google.com', 443)
    auth = 'lum-customer-c_9c799542-zone-protick-dns-remote:cbp4uaamzwpy'

    headers = {}
    headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')
    headers['Connection'] = 'Close'
    CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'

    try:
        s = socket.socket()
        s.connect(("zproxy.lum-superproxy.io", 22225))
        s.send(bytes(CONNECT, "utf-8"))
        resp = s.recv(4096)

        socket.setdefaulttimeout(8)

        # context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname='google.com')

        subdomain = None
        certs = s.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(certs)
        # cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        # san_dns_names = san.value.get_values_for_type(x509.DNSName)
        # subject = dict(item[0] for item in cert['subject'])
        # print(subject['commonName'])
        #
        # subjectAltName = defaultdict(set)
        # for type_, san in cert['subjectAltName']:
        #     subjectAltName[type_].add(san)
        # print(subjectAltName['DNS'])

        '''
        
            The CA/Browser Forum has since mandated that the SAN 
            would also include any value present in the common name, 
            effectively making the SAN the only required reference for a 
            certificate match with the server name.
            
            
            Update: as per RFC 6125, published in 2011, the validator 
            must check SAN first, and if SAN exists, then CN 
            should not be checked. Note that RFC 6125 is relatively 
            recent and there still exist certificates and CAs that 
            issue certificates, which include the "main" domain name in 
            CN and alternative domain names in SAN. In other words, by 
            excluding CN from validation if SAN is present, you can deny 
            some otherwise valid certificate.

        '''
        # base64.b64decode(base64.b64encode(certs).decode("utf-8")) == certs
        return (certs, resp.decode("utf-8"), subdomain)

    except Exception as e:
        print(e)
        return (None, None, None)


getCertificate()