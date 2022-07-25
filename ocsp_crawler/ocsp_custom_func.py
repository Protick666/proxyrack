""" A full cert chain is required to make a proper OCSP request. However,
 the ssl module for python 3.x does not support the get_peer_cert_chain()
 method. get_peer_cert_chain() is in flight: https://github.com/python/cpython/pull/17938

 For a short-term fix, I will use nassl to grab the full cert chain. """

from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gaierror, socket, timeout
from typing import Any, List
from urllib import error, request
from urllib.parse import urlparse
from pathlib import Path

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

import brotli
import asn1
from zstd import ZSTD_compress
import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ExtensionNotFound, ocsp
from cryptography.x509.oid import ExtensionOID
from nassl._nassl import OpenSSLError
from nassl.cert_chain_verifier import CertificateChainVerificationFailed
from nassl.ssl_client import (
    ClientCertificateRequested, OpenSslVerifyEnum, OpenSslVersionEnum, SslClient)
from validators import domain, url


class InitialConnectionError(Exception):
    """ Custom exception class to differentiate between
     initial connection errors and OpenSSL errors """
    pass


# Get the local path to the ca certs
path_to_ca_certs = Path(certifi.where())

openssl_errors: dict = {
    # https://github.com/openssl/openssl/issues/6805
     "1408F10B": "The remote host is not using SSL/TLS on the port specified."
    # TLS Fatal Alert 40 - sender was unable to negotiate an acceptable set of security
    # parameters given the options available
    ,"14094410": "SSL/TLS Handshake Failure."
    # TLS Fatal Alert 112 - the server understood the ClientHello but did not recognize
    # the server name per: https://datatracker.ietf.org/doc/html/rfc6066#section-3
    ,"14094458": "Unrecognized server name provided. Check your target and try again."
    # TLS Fatal Alert 50 - a field was out of the specified range
    # or the length of the message was incorrect
    ,"1417B109": "Decode Error. Check your target and try again."
    # TLS Fatal Alert 80 - Internal Error
    ,"14094438": "TLS Fatal Alert 80 - Internal Error."
    # Unable to find public key parameters
    ,"140070EF": "Unable to find public key parameters."
}


async def get_ocsp_status(host, session) -> list:
    """Main function with two inputs: host, and port.
    Port defaults to TCP 443"""

    port = 443

    results: list = []
    results.append(f"Host: {host}:{port}")

    # pylint: disable=W0703
    # All of the exceptions in this function are passed-through

    # # Validate port
    # try:
    #     port = verify_port(port)
    #
    # except Exception as err:
    #     results.append("Error: " + str(err))
    #     return results

    # Sanitize host
    try:
        host = verify_host(host)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        # Get the remote certificate chain
        cert_chain = get_certificate_chain(host, port)

        # Extract OCSP URL from leaf certificate
        ocsp_url = extract_ocsp_url(cert_chain)

        # Build OCSP request
        ocsp_request = build_ocsp_request(cert_chain)

        # Send OCSP request to responder and get result
        ocsp_response = await get_ocsp_response(ocsp_url, ocsp_request, session)

        # Extract OCSP result from OCSP response

        # youtube_response_str = "48,130,1,212,10,1,0,160,130,1,205,48,130,1,201,6,9,43,6,1,5,5,7,48,1,1,4,130,1,186,48,130,1,182,48,129,159,162,22,4,20,138,116,127,175,133,205,238,149,205,61,156,208,226,70,20,243,113,53,29,39,24,15,50,48,50,50,48,54,51,48,49,53,53,54,52,57,90,48,116,48,114,48,74,48,9,6,5,43,14,3,2,26,5,0,4,20,199,46,121,138,221,255,97,52,179,186,237,71,66,184,187,198,192,36,7,99,4,20,138,116,127,175,133,205,238,149,205,61,156,208,226,70,20,243,113,53,29,39,2,17,0,170,155,242,217,87,9,63,113,18,239,228,43,82,100,3,110,128,0,24,15,50,48,50,50,48,54,51,48,49,53,53,54,52,57,90,160,17,24,15,50,48,50,50,48,55,48,55,49,52,53,54,52,56,90,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,1,1,0,182,136,101,111,15,253,181,196,157,12,46,161,31,91,51,113,246,230,212,140,175,30,196,113,70,11,134,97,238,141,213,26,154,58,142,23,2,214,18,6,65,117,92,157,46,133,232,241,209,154,158,82,125,240,232,206,246,224,249,226,214,67,137,199,193,70,141,1,79,232,145,230,221,55,69,164,104,73,14,213,26,175,75,42,252,51,201,58,138,27,247,5,248,4,2,84,127,21,180,10,135,192,111,115,56,81,109,168,215,142,67,94,46,48,111,177,201,158,161,48,239,170,195,201,244,65,45,94,157,171,55,184,190,200,57,207,203,190,16,15,22,205,239,69,21,150,25,157,247,70,241,120,111,212,40,135,157,180,72,9,106,247,217,218,25,205,210,113,239,6,158,165,175,247,101,216,243,49,33,149,144,214,253,129,114,92,159,57,156,178,57,36,222,96,140,190,141,66,172,52,128,220,64,231,54,40,162,44,113,170,103,114,216,224,31,174,160,196,172,240,93,207,3,25,171,158,103,43,247,115,84,79,85,51,226,101,152,122,12,224,39,226,4,99,84,240,140,133,106,61,209,7,26,189,139,59"
        #
        # youtube_response_bytes_ = youtube_response_str.split(",")
        #
        # youtube_response_bytes_ = [int(e) for e in youtube_response_bytes_]
        #
        # youtube_response_bytes = bytes(youtube_response_bytes_)

        ocsp_result, has_cert, resp_class, responder_key_hash, issuer_key_hash = extract_ocsp_result(ocsp_response)


    except Exception as err:
        print(err)
        results.append("Error: " + str(err))
        return results

    results.append(f"OCSP URL: {ocsp_url}")
    results.append(f"{ocsp_result}")

    # if has_cert:
    #
    #     cert = resp_class.certificates[0]
    #     cert_der_encoded_bytes = cert.public_bytes(serialization.Encoding.DER)
    #     compressed_bytes = brotli.compress(data=cert_der_encoded_bytes, quality=11)
    #
    #     decoder = asn1.Decoder()
    #     decoder.start(cert_der_encoded_bytes)
    #     tag, value = decoder.read()
    #     a = 1
    #
    #     f = open('ocsp_bytes', 'wb')
    #     f.write(ocsp_response)
    #     f.close()
    #
    #     f = open('cert_bytes', 'wb')
    #     f.write(cert_der_encoded_bytes)
    #     f.close()

    # resp_class.certificates[0].tbs_certificates_bytes

    return results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash, ocsp_url


def get_certificate_chain(host: str, port: int) -> List[str]:

    """Connect to the host on the port and obtain certificate chain"""

    func_name: str = "get_certificate_chain"

    port = port or 443

    cert_chain: list = []

    soc = socket(AF_INET, SOCK_STREAM, proto=0)
    soc.settimeout(3)

    try:
        soc.connect((host, port))

    except gaierror:
        raise InitialConnectionError(
            f"{func_name}: {host}:{port} is invalid or not known."
        ) from None

    except timeout:
        raise InitialConnectionError(
            f"{func_name}: Connection to {host}:{port} timed out."
        ) from None

    except ConnectionRefusedError:
        raise InitialConnectionError(f"{func_name}: Connection to {host}:{port} refused.") from None

    except OSError:
        raise InitialConnectionError(
            f"{func_name}: Unable to reach the host {host}."
        ) from None

    except (OverflowError, TypeError):
        raise InitialConnectionError(
            f"{func_name}: Illegal port: {port}. Port must be between 0-65535."
        ) from None

    ssl_client = SslClient(
        ssl_version=OpenSslVersionEnum.SSLV23,
        underlying_socket=soc,
        ssl_verify=OpenSslVerifyEnum.NONE,
        ssl_verify_locations=path_to_ca_certs
    )

    # Add Server Name Indication (SNI) extension to the Client Hello
    ssl_client.set_tlsext_host_name(host)

    try:
        ssl_client.do_handshake()
        cert_chain = ssl_client.get_verified_chain()

    except IOError:
        raise ValueError(
            f"{func_name}: {host} did not respond to the Client Hello."
        ) from None

    except CertificateChainVerificationFailed:
        raise ValueError(f"{func_name}: Certificate Verification failed for {host}.") from None

    except ClientCertificateRequested:
        raise ValueError(f"{func_name}: Client Certificate Requested for {host}.") from None

    except OpenSSLError as err:
        for key, value in openssl_errors.items():
            if key in err.args[0]:
                raise ValueError(f"{func_name}: {value}"
            ) from None

        raise ValueError(f"{func_name}: {err}") from None

    finally:
        # shutdown() will also close the underlying socket
        ssl_client.shutdown()

    return cert_chain


def extract_ocsp_url(cert_chain: List[str]) -> str:

    """Parse the leaf certificate and extract the access method and
    access location AUTHORITY_INFORMATION_ACCESS extensions to
    get the ocsp url"""

    func_name: str = "extract_ocsp_url"

    ocsp_url: str = ""

    # Convert to a certificate object in cryptography.io
    certificate = x509.load_pem_x509_certificate(
        str.encode(cert_chain[0]), default_backend()
    )

    # Check to ensure it has an AIA extension and if so, extract ocsp url
    try:
        aia_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        # pylint: disable=protected-access
        for aia_method in iter((aia_extension)):
            if aia_method.__getattribute__("access_method")._name == "OCSP":
                ocsp_url = aia_method.__getattribute__("access_location").value

        if ocsp_url == "":
            raise ValueError(
                f"{func_name}: OCSP URL missing from Certificate AIA Extension."
            )

    except ExtensionNotFound:
        raise ValueError(
            f"{func_name}: Certificate AIA Extension Missing. Possible MITM Proxy."
        ) from None

    return ocsp_url


def build_ocsp_request(cert_chain: List[str]) -> bytes:

    """Build an OCSP request out of the leaf and issuer pem certificates
    see: https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPRequestBuilder
    for more information"""

    func_name: str = "build_ocsp_request"

    try:
        leaf_cert = x509.load_pem_x509_certificate(
            str.encode(cert_chain[0]), default_backend()
        )
        issuer_cert = x509.load_pem_x509_certificate(
            str.encode(cert_chain[1]), default_backend()
        )

    except ValueError:
        raise Exception(f"{func_name}: Unable to load x509 certificate.") from None

    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, SHA1())
    ocsp_data = builder.build()
    ocsp_request_data = ocsp_data.public_bytes(serialization.Encoding.DER)

    return ocsp_request_data


async def get_ocsp_response(ocsp_url, ocsp_request_data, session):
    a = 1
    """Send OCSP request to ocsp responder and retrieve response"""

    func_name: str = "get_ocsp_response"

    # Confirm that the ocsp_url is a valid url
    if not url(ocsp_url):
        raise Exception(f"{func_name}: URL failed validation for {ocsp_url}")

    try:
        a = 1
        ocsp_url = ocsp_url
        async with session.post(url=ocsp_url,
                                data=ocsp_request_data, headers={"Content-Type": "application/ocsp-request"}) as response:
            # print("yo")
            result_data = await response.read()
            a = 1
            return result_data

    except Exception as err:
        pass

    return result_data


def get_delegated_certs_public_key_hash(ocsp_response):
    a = 1
    for extension in ocsp_response.certificates[0].extensions:
        oid_str = extension.oid.dotted_string
        if oid_str == '2.5.29.14':
            return extension.value.digest.hex()
    return "-"

def extract_ocsp_result(ocsp_response):

    """Extract the OCSP result from the provided ocsp_response"""

    func_name: str = "extract_ocsp_result"

    try:
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response)
        # OCSP Response Status here:
        # https://cryptography.io/en/latest/_modules/cryptography/x509/ocsp/#OCSPResponseStatus
        # A status of 0 == OCSPResponseStatus.SUCCESSFUL
        if str(ocsp_response.response_status.value) != "0":
            # This will return one of five errors, which means connecting
            # to the OCSP Responder failed for one of the below reasons:
            # MALFORMED_REQUEST = 1
            # INTERNAL_ERROR = 2
            # TRY_LATER = 3
            # SIG_REQUIRED = 5
            # UNAUTHORIZED = 6
            ocsp_response = str(ocsp_response.response_status)
            ocsp_response = ocsp_response.split(".")
            raise Exception(f"{func_name}: OCSP Request Error: {ocsp_response[1]}")

        certificate_status = str(ocsp_response.certificate_status)
        certificate_status = certificate_status.split(".")
        has_cert = len(ocsp_response.certificates) > 0

        if has_cert:
            responder_key_hash = get_delegated_certs_public_key_hash(ocsp_response)
        else:
            responder_key_hash = "N/A"
        # ocsp_response.responder_key_hash.hex()
        if has_cert:
            a = 1
        return f"OCSP Status: {certificate_status[1]}", has_cert, ocsp_response, responder_key_hash, ocsp_response.issuer_key_hash.hex()

    except ValueError as err:
        return f"{func_name}: {str(err)}"


def verify_port(port: Any) -> int:
    """Check port for type and validity"""

    if not isinstance(port, int):
        if port.isnumeric() is False:
            raise Exception(f"Invalid port: '{port}'. Port must be between 0-65535.")

    _port = int(port)

    if _port > 65535 or _port == 0:
        raise Exception(f"Invalid port: '{port}'. Port must be between 0-65535.")

    return _port


def verify_host(host: str) -> str:
    """Parse a DNS name to ensure it does not contain http(s)"""
    parsed_name = urlparse(host)

    # The below parses out http(s) from a name
    host_candidate = parsed_name.netloc
    if host_candidate == "":
        host_candidate = parsed_name.path

    # The below ensures a valid domain was supplied
    if not domain(host_candidate):
        raise Exception(f"{host} is not a valid FQDN.")

    return host_candidate
