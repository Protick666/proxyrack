import json
from csv import reader
import gevent.monkey

gevent.monkey.patch_all()
from gevent.pool import Pool
import base64
import socket
import ssl
socket.setdefaulttimeout(2)
from pathlib import Path
from multiprocessing.pool import ThreadPool

mother_list = []


def fetch(web_cn_tuple):
    try:
        web, cn = web_cn_tuple
        CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % (web, 443)
        auth = 'lum-customer-c_9c799542-zone-protick-dns-remote-country-{}:cbp4uaamzwpy'.format(cn)
        headers = {}
        headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')
        headers['Connection'] = 'Close'
        CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'

        try:
            s = socket.socket()
            # s.settimeout(2)
            s.connect(("zproxy.lum-superproxy.io", 22225))
            s.send(bytes(CONNECT, "utf-8"))
            resp = s.recv(4096)
            # context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=web)
            # s.settimeout(2)
            cert_bytes = s.getpeercert(binary_form=True)
            cert_str = base64.b64encode(cert_bytes).decode("utf-8")
            # base64.b64decode(base64.b64encode(certs).decode("utf-8")) == certs
            to_Save_tuple = (web, cn, cert_str)
            mother_list.append(to_Save_tuple)
        except:
            pass
    except:
        pass

def get_chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


def fetch_top_websites(total):
    websites = []
    with open('data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append(row[1])
    # return [(1, 'google.com')]
    return websites[: total]


def get_lum_country_codes():
    f = open("data/country.json")
    d = json.load(f)
    country_codes = []
    for e in d:
        country_codes.append(d[e]["cc"])
    return country_codes


def finish_task(chunk, index, crom):
    global mother_list
    # POOL_SIZE = len(chunk)
    # pool = Pool(POOL_SIZE)

    #
    # green_lets = []
    # for scraper_id in range(0, len(chunk)):
    #     green_lets.append(gevent.spawn(fetch, chunk[scraper_id]))
    # gevent.joinall(green_lets, timeout=4)

    pool = ThreadPool(processes=1)
    async_results = []
    for scraper_id in range(0, len(chunk)):
         async_results.append(pool.apply_async(fetch, chunk[scraper_id]))
    for e in async_results:
        e.get(2)
    a = 1



    save_path = "cert_crawl/{}/".format(index)
    Path(save_path).mkdir(parents=True, exist_ok=True)
    with open(save_path + "{}.json".format(crom), "w") as ouf:
        json.dump(mother_list, fp=ouf)
    mother_list = []
    print(crom)


def init_point(index):
    websites = fetch_top_websites(1000000)
    chunks = get_chunks(websites, len(websites) // 4)
    chosen_chunk = chunks[index - 1]
    country_codes = get_lum_country_codes()
    tuple_list = []

    total_countries = len(country_codes)
    for website in chosen_chunk:
        for country_code in country_codes:
            tuple_list.append((website, country_code))

    actionable_chunks = get_chunks(tuple_list, 20 * total_countries)

    crom = 1
    for chunk in actionable_chunks:
        finish_task(chunk, index=index, crom=crom)
        crom += 1


init_point(2)




