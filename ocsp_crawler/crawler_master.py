
# ocsp_request, response, hascert = ocspchecker.get_ocsp_status(website)
from csv import reader
import asyncio
from common_tools import *
from aiohttp import ClientSession
import time
from pathlib import Path

CHUNK = 500

mother_dict = {}

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
    try:
        rank, website = website_rank_tuple
        from ocsp_custom_func import get_ocsp_status
        # results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash, ocsp_url
        results, ocsp_response, has_cert, responder_key_hash, issuer_key_hash, ocsp_url = await get_ocsp_status(website, session)
        response_len = len(ocsp_response)
        print(response_len)

        mother_dict[website] = {
            "rank": rank,
            "size": response_len,
            "responder_key_hash": responder_key_hash,
            "issuer_key_hash": issuer_key_hash,
            "responder_url": ocsp_url,
            "has_cert": has_cert
        }

    except Exception as e:
        print(e)


async def fetch_all(websites):
    tasks = []
    async with ClientSession() as session:
        for website in websites:
            task = asyncio.ensure_future(fetch(website, session))
            tasks.append(task)
        _ = await asyncio.gather(*tasks)


def fetch_async(websites):
    loop = asyncio.get_event_loop()
    chunks = get_chunks(lst=websites, n=CHUNK)
    for chunk in chunks:
        asyncio.run(fetch_all(websites=chunk))


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
