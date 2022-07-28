import asyncio
from os.path import expanduser
import socket
import ssl
import certifi
from pathlib import Path
from check_tls_certs import *
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import redis

def tuple_test():
        domain_tuples = ('google.com', 'facebook.com', 'youtube.com')
        domains = list(itertools.chain(
                domain_definitions_from_filename(None),
                domain_definitions_from_cli(domain_tuples)))

        certs = get_domain_certs(domains)

        a = certs['google.com'][0].to_cryptography()
        pem = a.public_bytes(encoding=serialization.Encoding.PEM)
        cert = pem.decode('utf8')



# https://github.com/fschulze/check-tls-certs/blob/main/check_tls_certs.py

def get_certs_akid(cert):
    a = 1
    for extension in cert.extensions:
        oid_str = extension.oid.dotted_string
        if oid_str == '2.5.29.35':
            return extension.value.key_identifier.hex()
    return "-"

def get_certs_ocsp_url(cert):
    a = 1
    for extension in cert.extensions:
        oid_str = extension.oid.dotted_string
        if oid_str == '1.3.6.1.5.5.7.1.1':
            for sub_extension in extension.value._descriptions:
                if sub_extension.access_method.dotted_string == '1.3.6.1.5.5.7.48.1':
                    return sub_extension.access_location.value
    return "-"

async def tcp_echo_client(message):
    # We need a fully qualified domain name for the server.
    host = "facebook.com"
    # We need an SSL context.
    path_to_ca_certs = Path(certifi.where())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations(
        path_to_ca_certs
    )

    context.verify_mode = ssl.CERT_REQUIRED
    # context.check_hostname = True

    reader, writer = await asyncio.open_connection(
        host, # use the real host name
        443,
        ssl=context # pass in the context.
    )

    # We will get a certificate from the server.
    peercert = writer.get_extra_info('peercert')
    print(f'Peer cert: {peercert!r}')
    decoded_cert = x509.load_der_x509_certificate(peercert)
    akid = get_certs_akid(decoded_cert)
    serial = decoded_cert.serial_number
    ocsp_url = get_certs_ocsp_url(decoded_cert)
    a = 1


    redis_host = "pharah.cs.vt.edu"

    r = redis.Redis(host=redis_host, port=6379, db=0,
                    password="certificatesarealwaysmisissued")

    ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid.upper()).decode())

    a = 1
    writer.close()

asyncio.run(tcp_echo_client('Hello World!'))