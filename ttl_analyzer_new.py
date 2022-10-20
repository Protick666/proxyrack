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
            print(ip)
            pass


def preprocess_resolvers():
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    d = json.load(f)
    resolver_set = set()

    for ttl in allowed_ttl:
        for resolver in d[str(ttl)]['resolver_ip_to_verdict_list_dump']:
            resolver_set.add(resolver)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, list(resolver_set))
    pool.close()
    pool.join()


def table_maker():
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

            if total == 0:
                continue

            ratio = len(incorrect_set) / total

            if ratio >= 1:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                ans[org][0] += 1
                ans[org][1].update(total_set)
                cn[org] = cntry
                org_set.add(org)

            elif ratio <= 0:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                c_ans[org][0] += 1
                c_ans[org][1].update(total_set)
                cn[org] = cntry
                org_set.add(org)

        ans_lst = []

        for org in org_set:
            correct_count = 0
            in_correct_count = 0
            exitnode_set = set()
            if org in c_ans:
                correct_count = c_ans[org][0]
                exitnode_set = exitnode_set.union(c_ans[org][1])
            if org in ans:
                in_correct_count = ans[org][0]
                exitnode_set = exitnode_set.union(ans[org][1])

            ans_lst.append((correct_count, in_correct_count, len(exitnode_set), org, cn[org]))

        with open(parent_path + "table_data.json", "w") as ouf:
            json.dump(ans_lst, fp=ouf)



def geographic_correct_incorrect_distribution_all_over():

    inc_set = set()
    cor_set = set()
    all_set = set()

    for ttl in allowed_ttl:

        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            if total == 0:
                continue

            ratio = len(incorrect_set) / total

            if ratio >= 1:
                inc_set.add(key)
            elif ratio <= 0:
                cor_set.add(key)

    cor_set = cor_set.difference(inc_set)
    all_set = cor_set.union(inc_set)

    geo_distro = {}

    country_code_to_count_map = defaultdict(lambda: 0)

    for resolver in inc_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["incorrect"] = country_code_to_count_map

    country_code_to_count_map = defaultdict(lambda: 0)
    for resolver in cor_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["correct"] = country_code_to_count_map

    country_code_to_count_map = defaultdict(lambda: 0)
    for resolver in all_set:
        country_code_to_count_map[get_org_cn_from_ip(resolver)[1]] += 1
    geo_distro["all"] = country_code_to_count_map

    with open(parent_path + "geographic_corr_incorr_distro_global.json", "w") as ouf:
        json.dump(geo_distro, fp=ouf)

def init():
    start_time = time.time()
    preprocess_resolvers()
    analyzed_resolvers = time.time()
    print("Analyze analyzed_resolvers {}".format((analyzed_resolvers - start_time) / 60))

    table_maker()

    analyzed_table = time.time()
    print("Analyze table {}".format((analyzed_table - start_time) / 60))

    geographic_correct_incorrect_distribution_all_over()

    analyzed_geographic = time.time()
    print("Analyze geo {}".format((analyzed_geographic - start_time) / 60))



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

            if total == 0:
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

# init()