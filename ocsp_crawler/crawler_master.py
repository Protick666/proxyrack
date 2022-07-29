
# ocsp_request, response, hascert = ocspchecker.get_ocsp_status(website)
import ssl
from csv import reader
from pathlib import Path

import certifi
import redis
from aiohttp import ClientSession, ClientTimeout
from check_tls_certs import *
from cryptography import x509
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ
import time
import sys

web_to_cert_dict = {}


from ck_tls_certs import domain_definitions_from_filename, domain_definitions_from_cli
from common_tools import *
from pyasn1_modules import pem
from pyasn1_modules import rfc2459
from pyasn1_modules import rfc2560
from ocsp_custom_func import get_ocsp_status_from_response
from local import *
import random
import binascii
import hashlib

CHUNK = 1000

mother_dict = {}


if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST
    sys.stdout = open("test.txt", "w")
    sys.stderr = open("err.txt", "w")



r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")

sha1oid = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))


def makeOcspRequest(issuerCert, userSerialNumber=None, userCert=None, add_nonce=False):
    issuerTbsCertificate = issuerCert.getComponentByName('tbsCertificate')
    if (userCert is None):
        issuerSubject = issuerTbsCertificate.getComponentByName('subject')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    else:
        c = pem.readPemFromString(userCert)
        userCert, _ = decoder.decode(c, asn1Spec=rfc2459.Certificate())
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        issuerSubject = userTbsCertificate.getComponentByName('issuer')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName(
        'subjectPublicKey')

    issuerKeyHash = hashlib.sha1(issuerSubjectPublicKey.asOctets()).digest()

    if (userSerialNumber is None):
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')
        userSerialNumber = userTbsCertificate.getComponentByName('serialNumber')

    request = rfc2560.Request()
    reqCert = request.setComponentByName('reqCert').getComponentByName('reqCert')

    hashAlgorithm = reqCert.setComponentByName('hashAlgorithm').getComponentByName('hashAlgorithm')
    hashAlgorithm.setComponentByName('algorithm', sha1oid)

    reqCert.setComponentByName('issuerNameHash', issuerHash)
    reqCert.setComponentByName('issuerKeyHash', issuerKeyHash)
    reqCert.setComponentByName('serialNumber', str(int(userSerialNumber, 16)))

    ocspRequest = rfc2560.OCSPRequest()

    tbsRequest = ocspRequest.setComponentByName('tbsRequest').getComponentByName('tbsRequest')
    tbsRequest.setComponentByName('version', 'v1')

    if (add_nonce):
        requestExtensions = tbsRequest.setComponentByName('requestExtensions').getComponentByName('requestExtensions')

        extension = rfc2459.Extension()
        extension.setComponentByName('extnID', rfc2560.id_pkix_ocsp_nonce)
        extension.setComponentByName('critical', 0)

        nonce = "0410EAE354B142FE6DE525BE7708307F80C2"
        nonce = nonce[:-10] + str(int(time.time())) + str(random.randint(1, 100000))
        if len(nonce) % 2 == 1:
            nonce = nonce[: - 1]
        ## ASN1: Tag (04: Integer) - Length (10:16 bytes) - Value  Encoding
        ## See: http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art062
        ## current version of pyasn1_modules do not support nonce

        extension.setComponentByName('extnValue', binascii.unhexlify(nonce))

        requestExtensions.setComponentByPosition(0, extension)

    requestList = tbsRequest.setComponentByName('requestList').getComponentByName('requestList')
    requestList.setComponentByPosition(0, request)
    return ocspRequest


def fetch_top_websites(total):

    websites = []
    with open('data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append((row[0], row[1]))
    # return [(1, 'google.com')]
    return websites[: total]


async def fetch(website_rank_tuple, session):
    global mother_dict
    global web_to_cert_dict
    try:


        rank, website = website_rank_tuple
        if website not in web_to_cert_dict:
            return None

        serial, akid, ocsp_url = web_to_cert_dict[website]['serial'], web_to_cert_dict[website]['akid'], web_to_cert_dict[website]['ocsp_url']

        from ocsp_custom_func import get_ocsp_status

        ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
        ca_cert = pem.readPemFromString(ca_cert)
        issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

        ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial)),
                                  userCert=None, add_nonce=False)

        ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
        headers = get_ocsp_request_headers_as_tuples(ocsp_host=ocsp_host)

        async with session.post(url=ocsp_url,
                                data=encoder.encode(ocspReq), headers=headers) as response:
            result_data = await response.read()
            results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash = await get_ocsp_status_from_response(result_data)

        response_len = len(ocsp_response)

        mother_dict[website] = {
            "rank": rank,
            "size": response_len,
            "responder_key_hash": responder_key_hash,
            "issuer_key_hash": issuer_key_hash,
            "responder_url": ocsp_url,
            "has_cert": has_cert
        }

    except Exception as e:
        pass


async def fetch_cert(website):
    global web_to_cert_dict
    # web_to_cert_dict[website] = "BAL"
    try:
        # cert = ssl.get_server_certificate((website, 443))
        # a = 1
        # return cert

        """
            Cert fetch
        """

        host = website
        path_to_ca_certs = Path(certifi.where())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_verify_locations(
            path_to_ca_certs
        )
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        fut = asyncio.open_connection(
            host,  # use the real host name
            443,
            ssl=context,  # pass in the context.
        )

        reader, writer = await asyncio.wait_for(fut, timeout=10)

        peercert = writer.get_extra_info('peercert')
        decoded_cert = x509.load_der_x509_certificate(peercert)
        akid = get_certs_akid(decoded_cert)
        akid = akid.upper()
        ocsp_url = get_certs_ocsp_url(decoded_cert)
        serial = decoded_cert.serial_number
        writer.close()
        web_to_cert_dict[website] = {
            "akid": akid,
            "ocsp_url": ocsp_url,
            "serial": serial,
        }
        return True
        ###################################################################
    except Exception as e:
        a = 1
        return None


async def fetch_all(websites, cnt):
    a = 1
    domain_to_cert_chain = {}
    # rank, website = website_rank_tuple

    # domains = get_domain_tuple(websites)
    # certs = get_domain_certs(domains)
    #
    # certs = filter_cert_res(certs)
    # certs = pemify_certs(certs)
    # cert_dict = certs

    print("Init")
    tasks = []
    for website in websites:
        task = asyncio.ensure_future(fetch_cert(website[1]))
        tasks.append(task)
    all_cert = await asyncio.gather(*tasks)
    a = 1
    # a = 1
    print("Duos")

    tasks = []

    my_timeout = ClientTimeout(total=10)
    async with ClientSession(timeout=my_timeout) as session:
        for website in websites:
            task = asyncio.ensure_future(fetch(website, session))
            tasks.append(task)
        _ = await asyncio.gather(*tasks)

    print("Tres")

    global mother_dict
    global web_to_cert_dict

    Path("results").mkdir(parents=True, exist_ok=True)

    import json
    with open("results/website_summary_{}.json".format(cnt), "w") as ouf:
        json.dump(mother_dict, fp=ouf)

    mother_dict = {}
    web_to_cert_dict = {}


def get_domain_tuple(websites):
    domain_tuple_list = []
    for rank, website in websites:
        domain_tuple_list.append(website)
    domain_tuple = tuple(domain_tuple_list)

    domains = list(itertools.chain(
        domain_definitions_from_filename(None),
        domain_definitions_from_cli(domain_tuple)))
    return domains


def filter_cert_res(certs):
    ans = {}
    for key in certs:
        if type(certs[key]) == type([]) and str(type((certs[key][0]))) == '<class \'OpenSSL.crypto.X509\'>':
            ans[key] = certs[key]
    return ans


def pemify_certs(certs):
    from cryptography.hazmat.primitives import serialization

    # certs = get_domain_certs(domains)
    #
    # a = certs['google.com'][0].to_cryptography()
    # pem = a.public_bytes(encoding=serialization.Encoding.PEM)
    # cert = pem.decode('utf8')
    ans = {}
    for key in certs:
        tmp = []
        for c in certs[key]:
            a = c.to_cryptography()
            pem = a.public_bytes(encoding=serialization.Encoding.PEM)
            str = pem.decode('utf8')
            tmp.append(str)
        ans[key] = tmp
    return ans


def fetch_async(websites):
    chunks = get_chunks(lst=websites, n=CHUNK)
    c_index = 0
    for chunk in chunks:
        init = time.time()

        asyncio.run(fetch_all(websites=chunk, cnt=c_index))

        delta = time.time() - init
        print("time taken for chunk {}  {}".format(c_index, delta))
        c_index += 1


def init():
    global mother_dict
    init = time.time()
    top_websites = fetch_top_websites(total=1000000)
    fetch_async(websites=top_websites)
    delta = time.time() - init
    a = 1


init()
if not LOCAL:
    sys.stdout.close()
