import os
import json
from fastavro import writer, reader, parse_schema

target_domains = set()
res = {}

CDNs = ['Akamai',
        "Akam",
        'Akadns',
        'Bitgravity',
        'Cachefly',
        'CDN77',
        'CDNetworks',
        'CDNify',
        'ChinaCache',
        'ChinaNetCenter',
        'EdgeCast',
        'Fastly',
        'Highwinds',
        'Internap',
        'KeyCDN',
        'google',
        'Level3',
        'Limelight',
        'MaxCDN',
        'NetDNA',
        'Telefónica',
        'XCDN',
        'CloudFlare',
        "Cloudfront",
        'Jetpack',
        'CloudLayer',
        'CloudCache',
        'TinyCDN',
        'Incapsula',
        'jsDelivr',
        'EdgeCast',
        'CDNsun',
        'Limelight',
        'Azure',
        'CDNlio',
        'SoftLayer',
        'ITWorks',
        'CloudOY',
        'Octoshape',
        'Hibernia',
        'WebMobi',
        'CDNvideo',
        'zerocdn',
        "alibaba",
        "netlify",
        "wixdns",
        "tiny",
        'Rackspace',
        "cedexis",
    "Mlytics",
    "metacdn",
    "atanar",
        "CDN",
        "cdn",
        ]


# multicdns = [
#     "cedexis",
#     "Mlytics",
#     "metacdn",
#     "atanar",
# ]

from collections import defaultdict

cdn_to_domains = defaultdict(lambda : set())
cdn_to_ttls = defaultdict(lambda : list())



def json_dump(d, fn):
    json.dump(d, open(fn, 'w'), default=str, indent=4)

def proc_f(f):
    global target_domains
    global res

    cnt = 0
    with open(os.path.join('/tmp', f), 'rb') as fo:
        for domain in reader(fo):
            cnt += 1
            if cnt % 10000 == 0:
                print(cnt)
            if domain['cname_name'] is not None and \
                    domain['query_type'] == "A" and \
                    domain['response_type'] == "CNAME":

                for cdn in CDNs:
                    if cdn.lower() in domain['cname_name']:
                        cdn_to_domains[cdn].add(domain['query_name'])
                        target_domains.add(domain['query_name'])
                        break

            if domain['query_type'] == "A" and \
                    domain['response_type'] == "A":
                res[domain['query_name']] = domain["response_ttl"]

    print("Done with {}".format(f))


from multiprocessing.dummy import Pool as ThreadPool


def get_tuple(ttl_list):

    counter = defaultdict(lambda : 0)
    total = len(ttl_list)
    if total == 0:
        return [(0, 0, 0)]
    arr = []

    for ttl in ttl_list:
        counter[ttl] += 1

    for ttl in counter:
        arr.append((ttl, counter[ttl], (counter[ttl] * 100)/total))

    arr.sort(key=lambda x: -x[1])
    return arr


if __name__ == "__main__":
    global res
    files = os.listdir('/tmp/')

    files_list = []
    for f in files:
        if f.endswith('.avro'):
            files_list.append(f)

    print("Total files {}".format(len(files_list)))

    pool = ThreadPool(10)
    results = pool.map(proc_f, files_list)
    pool.close()
    pool.join()

    for cdn in cdn_to_domains:
        for domain in cdn_to_domains[cdn]:
            try:
                cdn_to_ttls[cdn].append(res[domain])
            except:
                pass

    cdn_to_sorted_tuples = defaultdict(lambda: list())
    cdn_to_max_tuple = {}

    for cdn in cdn_to_ttls:
        try:
            tuple_list = get_tuple(cdn_to_ttls[cdn])
            cdn_to_sorted_tuples[cdn] = tuple_list
            cdn_to_max_tuple[cdn] = tuple_list[0]
        except:
            pass


    # json_dump(target_domains, 'target_v2.json')
    # json_dump(res, 'result_v2.json')

    json_dump(cdn_to_ttls, 'cdn_to_ttls.json')
    json_dump(cdn_to_sorted_tuples, 'cdn_to_sorted_tuples.json')
    json_dump(cdn_to_max_tuple, 'cdn_to_max_tuple.json')


if __name__ == "zx__main__":

    f = open("target_v2.json")
    target_domains = json.load(f)
    lst = target_domains.split(",")
    t_domains = set()
    for e in lst:
        domain = e[2:-1]
        t_domains.add(domain)


    f = open("result_v2.json")
    result = json.load(f)

    other_domains = list()
    cdn_domains = list()

    for key in result:
        if key in t_domains:
            cdn_domains.append(result[key])
        else:
            other_domains.append(result[key])

    with open("cdn_meta.json", "w") as ouf:
        json.dump({"cdn": cdn_domains, "non_cdn": other_domains}, fp=ouf)


