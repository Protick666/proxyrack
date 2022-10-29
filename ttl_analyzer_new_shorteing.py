'''
primary analysis done at new_ttl_parser.py from
/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json
keys -> 1 - 5 and global
d['60']['resolver_ip_to_verdict_list_dump']['202.144.211.161']['b']/['g'] -> list of exitnode hashes
'''

allowed_ttl = ["1", "5", "15", "30", "60"]
from collections import defaultdict
import json
import pyasn
from asn_org_tools.org_finder import AS2ISP
from multiprocessing.dummy import Pool as ThreadPool
import time
asndb = pyasn.pyasn('asn_org_tools/data/ipsan_db.dat')
as2isp = AS2ISP()


parent_path = "data/"
asn_to_org_cn = {}
ip_to_asn = {}


def get_verdict_list(ttl):
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    d = json.load(f)
    return d[str(ttl)]['resolver_ip_to_verdict_list_dump']


def get_asn(ip):
    if ip in ip_to_asn:
        return ip_to_asn[ip]
    asn = asndb.lookup(ip)[0]
    ip_to_asn[ip] = asn
    return asn


def get_org_cn(asn):
    if asn in asn_to_org_cn:
        return asn_to_org_cn[asn]
    org, cn = org = str(as2isp.getISP("20221212", asn)[0]), str(as2isp.getISP("20221212", asn)[1])
    asn_to_org_cn[asn] = org, cn
    return org, cn


ip_to_org_cn = {}


def get_org_cn_from_ip(ip):
    if ip in ip_to_org_cn:
        return ip_to_org_cn[ip]
    return -1, -1


def preprocess_resolver(ip):
    if ip not in ip_to_org_cn:
        try:
            asn = get_asn(ip)
            org, cn = get_org_cn(asn)
            ip_to_org_cn[ip] = org, cn
        except:
            # print(ip)
            pass


def preprocess_resolvers():
    resolver_list = []
    f = open("short/new/43/resolver_ip_to_verdict_list.json")
    d = json.load(f)
    resolver_list = resolver_list + list(d.keys())
    f = open("short/new/49/resolver_ip_to_verdict_list.json")
    d = json.load(f)
    resolver_list = resolver_list + list(d.keys())
    f = open("short/new/55/resolver_ip_to_verdict_list.json")
    d = json.load(f)
    resolver_list = resolver_list + list(d.keys())
    resolver_list = list(set(resolver_list))

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, resolver_list)
    pool.close()
    pool.join()


all_resolver_global = set()
all_asn_global = set()
all_exitnode_global = set()
all_cn_global = set()


def do_all(window):
    print("Window {}".format(window))
    f = open("short/new/{}/resolver_ip_to_verdict_list.json".format(window))
    d = json.load(f)

    all_resolver_local = set()
    all_asn_local = set()
    all_exitnode_local = set()
    all_cn_local = set()
    bad_set = set()
    good_set = set()

    arr = []

    for resolver in d:
        normal_set = set(d[resolver]['n'])
        short_set = set(d[resolver]['s'])
        # prefetch_set = set(d[resolver]['p'])
        normal_set = normal_set.difference(short_set)

        tot = len(normal_set) + len(short_set)
        asn = get_asn(resolver)
        org, cn = get_org_cn(asn)
        tot_exitnode_set = normal_set.union(short_set)

        all_resolver_global.add(resolver)
        all_asn_global.add(asn)
        all_exitnode_global.update(tot_exitnode_set)
        all_cn_global.add(cn)

        if tot < 5:
            continue
        arr.append(len(short_set)/tot)

        if arr[-1] >= 1:
            bad_set.add(resolver)
        if arr[-1] <= 0:
            good_set.add(resolver)

        all_resolver_local.add(resolver)
        all_asn_local.add(asn)
        all_exitnode_local.update(tot_exitnode_set)
        all_cn_local.add(cn)

    print("Total before: Resolvers {}, Exitnodes {}, ASNs {}, Contries {}".format(len(all_resolver_global),
                                                                                  len(all_exitnode_global),
                                                                                  len(all_asn_global),
                                                                                  len(all_cn_global)))

    print("Total after: Resolvers {}, Exitnodes {}, ASNs {}, Contries {}".format(len(all_resolver_local),
                                                                                  len(all_exitnode_local),
                                                                                  len(all_asn_local),
                                                                                  len(all_cn_local)))

    bad = 0

    for e in arr:
        if e >= 1:
            bad += 1
    print("{} / {} ({} %)".format(bad, len(arr), (bad/len(arr) * 100)))

    return good_set, bad_set



def init():
    start_time = time.time()
    preprocess_resolvers()
    analyzed_resolvers = time.time()
    print("Analyze analyzed_resolvers {}".format((analyzed_resolvers - start_time) / 60))

    good_set_55, bad_set_55 = do_all(55)
    good_set_49, bad_set_49 = do_all(49)
    good_set_43, bad_set_43 = do_all(43)

    bad_set_all = bad_set_55.union(bad_set_49).union(bad_set_43)

    to_dump = []
    for r in bad_set_all:
        to_dump.append((r, ip_to_asn[r]))

    with open(parent_path + "shortening_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump, fp=ouf)

    print("******************************************************")

    print(len(bad_set_55.intersection(bad_set_49)))
    print(len(bad_set_55.intersection(bad_set_43)))
    print(len(bad_set_43.intersection(bad_set_49)))

    print("******************************************************")

    print(len(good_set_55.intersection(bad_set_49)))
    print(len(good_set_55.intersection(bad_set_43)))
    print(len(good_set_49.intersection(bad_set_43)))


def find_one_min_dishonoring_resolvers():
    dishonoring_resolver_set = set()
    honoring_resolver_set = set()
    for ttl in ["1"]:
        final_dict = get_verdict_list(ttl)

        ans = defaultdict(lambda: [0, set()])
        c_ans = defaultdict(lambda: [0, set()])
        cn = {}
        org_set = set()

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            if total < 5:
                continue

            ratio = len(incorrect_set) / total

            if ratio >= 1:
                dishonoring_resolver_set.add(key)
            elif ratio <= 0:
                honoring_resolver_set.add(key)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, list(dishonoring_resolver_set) + list(honoring_resolver_set))
    pool.close()
    pool.join()

    to_dump = []
    to_dump_honor = []
    for r in dishonoring_resolver_set:
        to_dump.append((r, ip_to_asn[r]))
    for r in honoring_resolver_set:
        to_dump_honor.append((r, ip_to_asn[r]))

    with open(parent_path + "dishonring_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump, fp=ouf)
    with open(parent_path + "honring_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump_honor, fp=ouf)

# find_one_min_dishonoring_resolvers()

init()