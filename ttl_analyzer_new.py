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


f2 = open("alpha2.json")
d2 = json.load(f2)
alpha2_to_country = {}

for e in d2:
    c_code = e['country-code']
    a_2_code = e['alpha-2']
    alpha2_to_country[a_2_code] = e['name']

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


def table_maker_v2():
    org_to_local_count = defaultdict(lambda : 0)

    for ttl in ["1"]:

        final_dict = get_verdict_list(ttl)
        ans = defaultdict(lambda: [0, set()])
        c_ans = defaultdict(lambda: [0, set()])
        cn = {}
        org_set = set()

        for key in final_dict:
            if not is_local[key]:
                continue

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

                org_set.add(org)

            elif ratio <= 0:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                c_ans[org][0] += 1
                c_ans[org][1].update(total_set)
                cn[org] = cntry

                org_set.add(org)

        ans_lst = []

        country_to_meta = defaultdict(lambda : list())

        for org in org_set:
            cnn = cn[org]
            correct_count = 0
            in_correct_count = 0
            exitnode_set = set()
            incorrect_exitnode = set()
            correct_exitnode = set()

            if org in c_ans:
                correct_count = c_ans[org][0]
                exitnode_set = exitnode_set.union(c_ans[org][1])
                correct_exitnode.update(c_ans[org][1])
            if org in ans:
                in_correct_count = ans[org][0]
                exitnode_set = exitnode_set.union(ans[org][1])
                incorrect_exitnode.update(ans[org][1])



            meta = {
                "organization": org,
                "honoring_resolvers": correct_count,
                "extending_resolvers": in_correct_count,
                "percentage_of_extending_resolvers": (in_correct_count/(correct_count + in_correct_count)) * 100,
                "total_exitnodes": len(exitnode_set),
                "exitnodes_with_stale_response": len(incorrect_exitnode),
                "percentage_of_exitnodes_with_stale_response": (len(incorrect_exitnode)/len(exitnode_set)) * 100
            }
            # print(alpha2_to_country[cn])
            cd = cnn
            if cnn in alpha2_to_country:
                cd = alpha2_to_country[cnn]
            country_to_meta[cd].append(meta)
            #ans_lst.append((correct_count, in_correct_count, len(exitnode_set), org, cn[org]))

        with open(parent_path + "table_data_local.json", "w") as ouf:
            json.dump(country_to_meta, fp=ouf, indent=2)


def table_maker_v3():
    org_to_local_count = defaultdict(lambda : 0)
    resolver_to_ratio = {}
    resolver_to_tot = {}
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)

    tg_used_resolver_set = set()

    for ttl in ["1"]:

        final_dict = get_verdict_list(ttl)
        ans = defaultdict(lambda: [0, set()])
        c_ans = defaultdict(lambda: [0, set()])
        cn = {}
        org_set = set()

        for key in final_dict:
            # if not is_local[key]:
            #     continue

            correct_set = set()
            incorrect_set = set()

            for e in final_dict[key]["b"]:
                client_asn = ip_hash_to_asn[e]
                org, cntry = get_org_cn(client_asn)
                if cntry == 'TG':
                    tg_used_resolver_set.add(key)
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            # if total < 5:
            #     continue

            ratio = len(incorrect_set) / total
            resolver_to_ratio[key] = ratio
            resolver_to_tot[key] = total

        ans_lst = []

        for r in tg_used_resolver_set:
            print("Resolver: {}, Country: {}, ratio: {}, tot: {}".format(r, ip_to_org_cn[r], resolver_to_ratio[r], resolver_to_tot[r]))


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

all_cn = set()
bad_cn = set()

all_asn = set()
bad_asn = set()

def make_arr_v2(resolver_ip_to_verdict_list, ttl, ip_hash_to_asn):
    ttl_to_arr[ttl] = {}
    arr_global_local = []
    arr_global_public = []

    for resolver_ip in resolver_ip_to_verdict_list:
        cn_set = set()
        asn_set = set()

        good_len = len(resolver_ip_to_verdict_list[resolver_ip]["g"])
        bad_len = len(resolver_ip_to_verdict_list[resolver_ip]["b"])


        for e in resolver_ip_to_verdict_list[resolver_ip]["g"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            all_cn.add(cn)
            all_asn.add(asn)


        for e in resolver_ip_to_verdict_list[resolver_ip]["b"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            all_cn.add(cn)
            all_asn.add(asn)
            bad_asn.add(asn)
            bad_cn.add(cn)

    print_meta(arr_global_local, ttl, "local")
    print_meta(arr_global_public, ttl, "public")

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

        asn_counter = defaultdict(lambda : 0)

        all_considered_resolvers.add(resolver_ip)

        for e in resolver_ip_to_verdict_list[resolver_ip]["g"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            cn_set.add(cn)
            asn_set.add(asn)
            asn_counter[asn] += 1

        for e in resolver_ip_to_verdict_list[resolver_ip]["b"]:
            asn = ip_hash_to_asn[e]
            cn = get_org_cn(asn)[1]
            cn_set.add(cn)
            asn_set.add(asn)
            asn_counter[asn] += 1

        if len(cn_set) > 1:
            all_public_resolvers.add(resolver_ip)
            arr_global_public.append((bad_len / (good_len + bad_len)))
        else:
            asn_perc = []
            tot_cnt = 0
            for asn in asn_counter:
                tot_cnt += asn_counter[asn]
            for asn in asn_counter:
                asn_perc.append(asn_counter[asn] / tot_cnt)

            for e in asn_perc:
                if e >= .9:
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

def find_public_local_v2():
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    d = json.load(f)

    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)

    for ttl in allowed_ttl:
        p = d[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        make_arr_v2(p, ttl, ip_hash_to_asn)



def analyze_mixed():
    print("In it")
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/mother_info.json")
    p = json.load(f)

    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)

    potential_culprit_exitnodes = set()
    potential_culprit_asns = set()

    # potential_benign_exitnodes = set()
    # potential_benign_asns = set()

    exitnode_to_good_resolver_set = defaultdict(lambda : set())
    exitnode_to_bad_resolver_set = defaultdict(lambda : set())

    asn_to_bad_exitnode_set = defaultdict(lambda : set())
    asn_to_good_exitnode_set = defaultdict(lambda : set())

    for ttl in ["1"]:
        d = p[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        for resolver_ip in d:

            good_len = len(d[resolver_ip]["g"])
            bad_len = len(d[resolver_ip]["b"])

            for e in d[resolver_ip]["g"]:
                asn = ip_hash_to_asn[e]
                exitnode_to_good_resolver_set[e].add(resolver_ip)
                asn_to_good_exitnode_set[asn].add(e)

            for e in d[resolver_ip]["b"]:
                asn = ip_hash_to_asn[e]

                exitnode_to_bad_resolver_set[e].add(resolver_ip)
                asn_to_bad_exitnode_set[asn].add(e)

                if (0 < bad_len / (good_len + bad_len) < 1) and (good_len + bad_len > 5):
                    potential_culprit_exitnodes.add(e)
                    potential_culprit_asns.add(asn)


    solved_asns = set()
    solved_exitnodes = set()

    for asn in potential_culprit_asns:
        bad_ex = asn_to_bad_exitnode_set[asn]
        good_ex = asn_to_good_exitnode_set[asn].difference(bad_ex)

        if len(bad_ex)/(len(bad_ex) + len(good_ex)) > .9:
            # koyta resolver add korlo ??
            solved_asns.add(asn)
            solved_exitnodes.update(bad_ex)
            solved_exitnodes.update(good_ex)

    second_phase_solved_exitnodes = set()

    for e in potential_culprit_exitnodes:
        asn = ip_hash_to_asn[e]

        if asn in solved_asns:
            continue
        bad_re = exitnode_to_bad_resolver_set[e]
        good_re = exitnode_to_good_resolver_set[e].difference(bad_re)

        if len(bad_re)/(len(bad_re) + len(good_re)) >= .9 and (len(bad_re) + len(good_re)) > 1:
            # koyta resolver add korlo ??
            second_phase_solved_exitnodes.add(e)

    print("Solved asns {} along with exitnodes {}. Bad exitnodes {}".format(len(solved_asns), len(solved_exitnodes), len(second_phase_solved_exitnodes)))


    solved_resolvers_by_asns = set()
    solved_resolvers_by_exitnode = set()



    for ttl in ["1"]:
        d = p[str(ttl)]["resolver_ip_to_verdict_list_dump"]
        for resolver_ip in d:

            good_len = len(d[resolver_ip]["g"])
            bad_len = len(d[resolver_ip]["b"])
            if (good_len + bad_len > 5) and (0 < bad_len / (good_len + bad_len) < 1) :
                bad_asn_set = set()
                bad_ex_set = set()
                tot_bad = len(d[resolver_ip]["b"])
                solved_bad = set()
                for e in d[resolver_ip]["b"]:
                    asn = ip_hash_to_asn[e]
                    bad_asn_set.add(asn)
                    bad_ex_set.add(e)
                    if asn in solved_asns:
                        solved_bad.add(e)
                    if e in second_phase_solved_exitnodes:
                        solved_bad.add(e)

                if  len(solved_bad)/tot_bad > .8:
                    solved_resolvers_by_asns.add(resolver_ip)


    print("Solved resolvers {}".format(len(solved_resolvers_by_asns)))
    # print("Solved resolvers {}".format(len(solved_resolvers_by_exitnode)))






def init():
    start_time = time.time()
    preprocess_resolvers()
    analyzed_resolvers = time.time()
    print("Analyze analyzed_resolvers {}".format((analyzed_resolvers - start_time) / 60))

    # analyze_mixed()

    # find_public_local_v2()
    # print("{} {}".format(len(all_asn.difference(bad_asn)), len(all_cn.difference(bad_cn))))
    # print("{} {}".format(len(all_asn), len(all_cn)))

    find_public_local()

    # find_table_info()
    #
    # geographic_exitnode_fraction()
    #
    table_maker_v2()
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
    mixed_resolver_set = set()
    mixed_resolver_meta = []
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
            else:
                mixed_resolver_meta.append((key, ratio))
                mixed_resolver_set.add(key)


    pool = ThreadPool(30)
    results = pool.map(preprocess_resolver, list(dishonoring_resolver_set) + list(honoring_resolver_set))
    pool.close()
    pool.join()

    to_dump = []
    to_dump_honor = []
    to_dump_mixed = []
    for r in dishonoring_resolver_set:
        to_dump.append((r, ip_to_asn[r]))
    for r in honoring_resolver_set:
        to_dump_honor.append((r, ip_to_asn[r]))
    for r in mixed_resolver_set:
        to_dump_mixed.append((r, ip_to_asn[r]))

    with open(parent_path + "dishonring_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump, fp=ouf)
    with open(parent_path + "honring_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump_honor, fp=ouf)
    with open(parent_path + "mixed_ips_with_asns.json", "w") as ouf:
        json.dump(to_dump_mixed, fp=ouf)
    with open(parent_path + "mixed_ips_meta.json", "w") as ouf:
        json.dump(mixed_resolver_meta, fp=ouf)

# find_one_min_dishonoring_resolvers()

init()