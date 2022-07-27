
# ocsp_request, response, hascert = ocspchecker.get_ocsp_status(website)
from csv import reader
import asyncio
from common_tools import *
from aiohttp import ClientSession, ClientTimeout
import time
from pathlib import Path
from ck_tls_certs import domain_definitions_from_filename, domain_definitions_from_cli, get_domain_certs
import itertools
# import nest_asyncio
# nest_asyncio.apply()

CHUNK = 200

mother_dict = {}

def fetch_top_websites(total):

    websites = []
    with open('data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append((row[0], row[1]))
    # return [(1, 'google.com')]
    return websites[: total]


async def fetch(website_rank_tuple, session, cert_dict):
    global mother_dict
    try:
        rank, website = website_rank_tuple
        from ocsp_custom_func import get_ocsp_status
        # results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash, ocsp_url
        results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash, ocsp_url = await get_ocsp_status(website, session, cert_dict)
        response_len = len(ocsp_response)
        #print(response_len)

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
        #print(e)


async def fetch_all(websites, cert_dict):
    tasks = []

    domain_to_cert_chain = {}
    # rank, website = website_rank_tuple

    my_timeout = ClientTimeout(total=10)

    async with ClientSession(timeout=my_timeout) as session:
        for website in websites:
            task = asyncio.ensure_future(fetch(website, session, cert_dict))
            tasks.append(task)
        _ = await asyncio.gather(*tasks)


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
        domains = get_domain_tuple(chunk)
        certs = get_domain_certs(domains)
        certs = filter_cert_res(certs)
        certs = pemify_certs(certs)
        a = 1
        asyncio.run(fetch_all(websites=chunk, cert_dict=certs))
        a = 1
        delta = time.time() - init
        print("time taken for chunk {}  {}".format(c_index, delta))
        print(len(list(mother_dict.keys())))
        c_index += 1


def init():
    global mother_dict
    init = time.time()
    top_websites = fetch_top_websites(total=1000000)
    fetch_async(websites=top_websites)
    delta = time.time() - init
    a = 1

    Path("results").mkdir(parents=True, exist_ok=True)

    import json
    print("time taken {}".format(delta))
    with open("results/website_summary.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)

init()
