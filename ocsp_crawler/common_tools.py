def get_chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


def get_certs_akid(cert):
    a = 1
    for extension in cert.extensions:
        oid_str = extension.oid.dotted_string
        if oid_str == '2.5.29.35':
            return extension.value.key_identifier.hex()
    return "-"


def fix_cert_indentation(der_encoded_cert):
    l = len(der_encoded_cert)
    index = 0
    ultimate = "-----BEGIN CERTIFICATE-----\n"
    while index < l:
        ultimate = ultimate + der_encoded_cert[index: index + 64] + "\n"
        index += 64
    ultimate = ultimate + "-----END CERTIFICATE-----"
    return ultimate


def get_ocsp_request_headers_as_tuples(ocsp_host):
    headers = [('Connection', 'Keep-Alive'),
               ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
               ('User-Agent', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0"),
               ('Content-Type', 'application/ocsp-request'),
               ('Host', ocsp_host)]
    return headers

def get_certs_ocsp_url(cert):
    a = 1
    for extension in cert.extensions:
        oid_str = extension.oid.dotted_string
        if oid_str == '1.3.6.1.5.5.7.1.1':
            for sub_extension in extension.value._descriptions:
                if sub_extension.access_method.dotted_string == '1.3.6.1.5.5.7.48.1':
                    return sub_extension.access_location.value
    return "-"

def get_ocsp_host(ocsp_url):
    ocsp_host = ocsp_url
    if ocsp_host.startswith("http://"):
        ocsp_host = ocsp_host[7:]
    if "/" in ocsp_host:
        ocsp_host = ocsp_host[0: ocsp_host.find("/")]
    return ocsp_host