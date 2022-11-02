import os
import json
from fastavro import writer, reader, parse_schema

target_domains = set()
res = {}

CDNs = ['Akamai',
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
        'Jetpack',
        'Rackspace',
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
        "cdn",
        "alibaba",
        "netlify",
        "wixdns"
        ]

CDN_HINTS = ["Akam", "tiny", 'CDN', 'Cloudfront']

multicdns = [
    "cedexis",
    "Mlytics",
    "metacdn",
    "atanar",
]



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

                for cdn in CDNs + CDN_HINTS + multicdns:
                    if cdn.lower() in domain['cname_name']:
                        target_domains.add(domain['query_name'])

            if domain['query_type'] == "A" and \
                    domain['response_type'] == "A":
                res[domain['query_name']] = domain["response_ttl"]

    print("Done with {}".format(f))


from multiprocessing.dummy import Pool as ThreadPool

if __name__ == "__main__":
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


    json_dump(target_domains, 'target_v2.json')
    json_dump(res, 'result_v2.json')