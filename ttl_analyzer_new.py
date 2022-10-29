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


def preprocess_all_resolvers():
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/all_resolvers.json")
    d = json.load(f)
    resolver_list = list(d)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, resolver_list)
    pool.close()
    pool.join()

    asn_list = list()
    for resolver in resolver_list:
        asn_list.append(ip_to_asn[resolver])

    with open(parent_path + "resolver_asn_list.json", "w") as ouf:
        json.dump(asn_list, fp=ouf)

    with open(parent_path + "ip_to_asn_dict.json", "w") as ouf:
        json.dump(ip_to_asn, fp=ouf)


def preprocess_all_resolver_v2():
    f = open("/home/ashiq/PulseMaster/Outer_updates/temp/new_ttl_dnssec_expt_result.json")
    d = json.load(f)
    ans = set()
    for r in d:
        element_list = d[r]
        for n in element_list:
            ans.update(n['phase1_resolver_ips'])
            ans.update(n['phase2_resolver_ips'])

    resolver_list = list(ans)

    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, resolver_list)
    pool.close()
    pool.join()
    #
    # asn_list = list()
    # for resolver in resolver_list:
    #     asn_list.append(ip_to_asn[resolver])
    #
    # with open(parent_path + "resolver_asn_list.json", "w") as ouf:
    #     json.dump(asn_list, fp=ouf)

    with open(parent_path + "ip_to_asn_dict_ishtiaq.json", "w") as ouf:
        json.dump(ip_to_asn, fp=ouf)


def table_maker():

    org_to_local_count = defaultdict(lambda : 0)

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
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                ans[org][0] += 1
                ans[org][1].update(total_set)
                cn[org] = cntry

                if is_local[key]:
                    org_to_local_count[org] += 1

                org_set.add(org)

            elif ratio <= 0:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                c_ans[org][0] += 1
                c_ans[org][1].update(total_set)
                cn[org] = cntry

                if is_local[key]:
                    org_to_local_count[org] += 1

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

            local_count = org_to_local_count[org]
            local_perc = (local_count/(correct_count + in_correct_count)) * 100

            ans_lst.append((correct_count, in_correct_count, len(exitnode_set), org, cn[org], local_perc))

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

            if total < 5:
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


def geographic_exitnode_fraction():

    resolver_to_bad_exit_nodes = defaultdict(lambda: set())
    resolver_to_good_exit_nodes = defaultdict(lambda: set())

    country_to_good_exit_nodes = defaultdict(lambda: set())
    country_to_bad_exit_nodes = defaultdict(lambda: set())

    for ttl in allowed_ttl:
        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            correct_set = set()
            incorrect_set = set()
            for e in final_dict[key]["b"]:
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            resolver_to_bad_exit_nodes[key].update(incorrect_set)
            resolver_to_good_exit_nodes[key].update(correct_set)

    country_set = set()

    for resolver in resolver_to_bad_exit_nodes:
        cn = get_org_cn_from_ip(resolver)[1]
        country_set.add(cn)
        country_to_bad_exit_nodes[cn].update(resolver_to_bad_exit_nodes[resolver])

    for resolver in resolver_to_good_exit_nodes:
        cn = get_org_cn_from_ip(resolver)[1]
        country_set.add(cn)
        country_to_good_exit_nodes[cn].update(resolver_to_good_exit_nodes[resolver])

    country_to_meta = {}
    for cn in country_set:
        total_set = country_to_bad_exit_nodes[cn].union(country_to_good_exit_nodes[cn])
        bad_set = country_to_bad_exit_nodes[cn]
        if len(total_set) == 0:
            continue
        percentage_of_bad_exitnodes = (len(bad_set)/len(total_set)) * 100
        country_to_meta[cn] = (percentage_of_bad_exitnodes, len(bad_set), len(total_set))


    with open(parent_path + "geographic_exitnode_perc.json", "w") as ouf:
        json.dump(country_to_meta, fp=ouf)


all_resolver_global = set()
all_asn_global = set()
all_exitnode_global = set()


all_resolver_global_free = set()
all_asn_global_free = set()
all_exitnode_global_free = set()


all_considered_resolvers = set()
all_public_resolvers = set()
all_local_resolvers = set()

ttl_to_arr = {}

def print_meta(arr, ttl, str):
    good = 0
    bad = 0
    for e in arr:
        if e <=0:
            good += 1
        elif e >= 1:
            bad += 1
    print("TTL {}: {} : Bad {}, Good: {}, Tot: {}".format(ttl, str, bad, good, len(arr)))

is_local = defaultdict(lambda : False)

def make_arr(resolver_ip_to_verdict_list, ttl, ip_hash_to_asn):
    ttl_to_arr[ttl] = {}
    arr_global_local = []
    arr_global_public = []

    for resolver_ip in resolver_ip_to_verdict_list:
        cn_set = set()
        asn_set = set()

        good_len = len(resolver_ip_to_verdict_list[resolver_ip]["g"])
        bad_len = len(resolver_ip_to_verdict_list[resolver_ip]["b"])

        if good_len + bad_len < 5:
            continue

        all_considered_resolvers.add(resolver_ip)

        for e in resolver_ip_to_verdict_list[resolver_ip]["g"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            cn_set.add(cn)
            asn_set.add(asn)

        for e in resolver_ip_to_verdict_list[resolver_ip]["b"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            cn_set.add(cn)
            asn_set.add(asn)

        if len(cn_set) > 1:
            all_public_resolvers.add(resolver_ip)
            arr_global_public.append((bad_len / (good_len + bad_len)))
        elif len(asn_set) == 1:
            is_local[resolver_ip] = True
            all_local_resolvers.add(resolver_ip)
            arr_global_local.append((bad_len / (good_len + bad_len)))

    # ttl_to_arr[ttl]['local'] = arr_global_local
    # ttl_to_arr[ttl]['public'] = arr_global_public

    print_meta(arr_global_local, ttl, "local")
    print_meta(arr_global_public, ttl, "public")

def find_table_info():
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    d = json.load(f)

    for ttl in allowed_ttl:
        p = d[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        make_arr(p, ttl)

    print("TTL Gloabl: Total resolvers {}, Total ASNs {}, Total exitnodes: {}".format(len(all_resolver_global), len(all_asn_global), len(all_exitnode_global)) )

    print("TTL Global Free: Total resolvers {}, Total ASNs {}, Total exitnodes: {}".format(len(all_resolver_global_free), len(all_asn_global_free), len(all_exitnode_global_free)) )

    # all_resolver_global_free = set()
    # all_asn_global_free = set()
    # all_exitnode_global_free = set()


def find_public_local():
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    d = json.load(f)

    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)

    for ttl in allowed_ttl:
        p = d[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        make_arr(p, ttl, ip_hash_to_asn)

    # all_considered_resolvers = set()
    # all_public_resolvers = set()
    # all_local_resolvers = set()

    print("Tot {}, Public {}, Local {}".format(len(all_considered_resolvers),
                                               len(all_public_resolvers),
                                               len(all_local_resolvers)))


def init():
    start_time = time.time()
    preprocess_resolvers()
    analyzed_resolvers = time.time()
    print("Analyze analyzed_resolvers {}".format((analyzed_resolvers - start_time) / 60))

    find_public_local()

    # find_table_info()
    #
    # geographic_exitnode_fraction()
    #
    table_maker()
    #
    # analyzed_table = time.time()
    # print("Analyze table {}".format((analyzed_table - start_time) / 60))
    #
    # geographic_correct_incorrect_distribution_all_over()
    #
    # analyzed_geographic = time.time()
    # print("Analyze geo {}".format((analyzed_geographic - start_time) / 60))


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