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
    org, cn = str(as2isp.getISP("20221212", asn)[0]), str(as2isp.getISP("20221212", asn)[1])
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
    f = open("/home/ashiq/PulseMaster/Outer_updates/temp/resolver-list.json")
    d = json.load(f)

    resolver_list = list(d)

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
    print("Done")


preprocess_all_resolver_v2()

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
            # # 41.207.169.3
            # if key == "41.207.169.3":
            #     print("got here")

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

            # 41.207.169.3

            if key == "41.207.169.35":
                print("ratio {}/ {}".format(ratio, total))

            if ratio >= 1:
                asn = get_asn(key)
                org, cntry = get_org_cn(asn)
                ans[org][0] += 1
                ans[org][1].update(total_set)
                cn[org] = cntry
                # print(org)
                org_set.add(org)

                if cntry == 'BR':
                    print(key, cntry, total)

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

        header = ['country', 'organization', 'extending_resolvers', 'total_resolvers',
                  'percentage_of_extending_resolvers',
                  'exitnodes_with_stale_response', 'total_exitnodes',
                  'percentage_of_exitnodes_with_stale_response']

        import csv
        with open(parent_path + 'ttl_extension_organization_table.csv', 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            import csv
            writer.writerow(header)
            for cn in country_to_meta:
                for e in country_to_meta[cn]:
                    row = [cn, e['organization'], e['extending_resolvers'], e['honoring_resolvers'] + e['extending_resolvers'], e['percentage_of_extending_resolvers'],
                           e['exitnodes_with_stale_response'], e['total_exitnodes'],
                           e['percentage_of_exitnodes_with_stale_response']]
                    writer.writerow(row)

        with open(parent_path + "table_data_local.json", "w") as ouf:
            json.dump(country_to_meta, fp=ouf, indent=2)


def get_client_to_country_distro():
    print("Yo")
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)
    cn_to_exitnode_set = defaultdict(lambda: set())
    exitnode_set = set()
    cn_to_perc_list = []
    for ttl in allowed_ttl:
        final_dict = get_verdict_list(ttl)

        for key in final_dict:
            for e in final_dict[key]["b"]:
                client_asn = ip_hash_to_asn[e]
                exitnode_set.add(e)
                org, cntry = get_org_cn(client_asn)
                cn_to_exitnode_set[cntry].add(e)

            for e in final_dict[key]["g"]:
                client_asn = ip_hash_to_asn[e]
                exitnode_set.add(e)
                org, cntry = get_org_cn(client_asn)
                cn_to_exitnode_set[cntry].add(e)

    for cn in cn_to_exitnode_set:
        cn_to_perc_list.append((len(cn_to_exitnode_set[cn])/len(exitnode_set), cn, len(cn_to_exitnode_set[cn])))
    cn_to_perc_list.sort(reverse=True)

    print(len(exitnode_set))

    with open("cn_to_perc_list.json", "w") as ouf:
        json.dump(cn_to_perc_list, fp=ouf)


def table_maker_v3():
    org_to_local_count = defaultdict(lambda : 0)
    resolver_to_ratio = {}
    resolver_to_tot = {}
    f = open("/home/protick/ocsp_dns_tools/ttl_new_results/ip_hash_to_asn_global.json")
    ip_hash_to_asn = json.load(f)

    tg_used_resolver_set = set()

    resolver_to_asn_counter = defaultdict(lambda : defaultdict(lambda : 0))

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
                resolver_to_asn_counter[key][client_asn] += 1
                org, cntry = get_org_cn(client_asn)
                if cntry == 'TG':
                    tg_used_resolver_set.add(key)
                incorrect_set.add(e)
            for e in final_dict[key]["g"]:
                client_asn = ip_hash_to_asn[e]
                resolver_to_asn_counter[key][client_asn] += 1
                correct_set.add(e)

            total_set = correct_set.union(incorrect_set)
            total = len(total_set)

            # if total < 5:
            #     continue

            if total > 0:
                ratio = len(incorrect_set) / total
            else:
                ratio = "n/a"

            resolver_to_ratio[key] = ratio
            resolver_to_tot[key] = total

        ans_lst = []

        p = ""
        for r in tg_used_resolver_set:
            s = "Resolver: {}, Country: {}, ratio: {}, tot: {}, is_local: {}\n".format(r, ip_to_org_cn[r], resolver_to_ratio[r], resolver_to_tot[r], is_local[r])
            p  = p + s

        print("41.207.169.35", ip_to_asn["41.207.169.35"], resolver_to_asn_counter['41.207.169.35'])
        print("41.207.169.3", ip_to_asn["41.207.169.3"], resolver_to_asn_counter['41.207.169.35'])
        with open(parent_path + "togo.json", "w") as ouf:
            json.dump({"p": p}, fp=ouf)


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


dnssec_invalidating_resolvers = ['177.185.212.235', '138.117.48.248', '212.19.3.4', '194.69.174.37', '195.175.120.17', '45.228.123.243', '45.224.72.14', '201.175.130.251', '83.255.224.7', '154.52.12.115', '131.108.32.67', '83.217.192.2', '186.224.0.20', '213.87.99.131', '154.52.12.102', '177.86.136.6', '77.241.110.126', '143.208.178.10', '45.168.131.3', '138.0.172.52', '45.233.207.252', '179.125.107.2', '177.8.142.10', '45.234.44.2', '80.77.144.11', '45.232.196.27', '179.106.85.244', '192.221.142.137', '193.232.225.51', '91.192.88.72', '191.102.192.252', '201.62.80.231', '201.139.92.3', '200.81.41.9', '203.142.84.220', '177.128.87.6', '185.56.208.97', '192.142.128.11', '143.255.64.2', '45.233.200.6', '176.98.128.3', '177.126.76.6', '45.11.63.193', '45.233.186.131', '177.126.64.6', '212.188.20.72', '178.155.7.37', '213.87.70.149', '91.132.218.1', '88.87.231.252', '203.142.82.206', '196.202.252.61', '103.58.161.3', '177.36.64.4', '83.219.128.11', '177.67.232.1', '177.130.16.6', '45.168.180.18', '81.23.24.102', '149.255.83.7', '77.76.144.10', '45.165.140.12', '45.160.152.30', '194.69.172.72', '138.186.128.38', '103.83.176.140', '195.49.242.79', '177.184.216.28', '177.74.144.8', '62.169.176.3', '138.121.107.227', '177.107.96.240', '186.224.86.250', '170.231.108.6', '168.195.161.142', '168.227.136.6', '109.71.213.31', '212.156.199.13', '98.128.143.110', '170.254.36.8', '47.254.170.30', '81.6.139.82', '213.140.228.30', '185.210.36.4', '177.10.168.12', '177.200.85.171', '143.202.29.142', '189.84.159.73', '212.93.97.91', '190.15.222.33', '203.113.1.12', '83.223.5.3', '80.235.1.37', '103.19.57.3', '45.175.147.11', '37.46.121.239', '168.232.5.22', '77.95.207.210', '186.251.165.226', '193.192.98.12', '89.28.1.1', '87.216.0.164', '62.179.14.231', '211.138.19.82', '91.197.11.10', '186.219.219.150', '45.70.156.7', '45.228.120.6', '41.223.163.180', '77.95.200.12', '187.63.215.2', '85.143.105.114', '93.175.192.22', '189.1.144.13', '62.4.96.147', '41.219.71.181', '103.233.152.42', '190.104.14.42', '91.218.194.121', '154.52.12.118', '168.90.4.35', '154.52.12.106', '93.184.192.1', '80.74.194.10', '212.65.140.144', '45.168.153.56', '160.75.70.17', '23.91.3.202', '185.49.111.251', '45.170.5.115', '85.14.32.248', '186.192.79.218', '156.154.35.145', '80.74.194.2', '85.117.64.10', '82.151.98.154', '185.56.209.42', '114.141.52.226', '200.49.28.254', '195.158.222.66', '45.234.44.6', '45.233.60.5', '182.176.100.133', '106.241.8.97', '46.160.135.186', '91.235.101.3', '45.167.136.100', '45.177.224.254', '201.55.200.1', '195.74.2.4', '45.238.224.58', '200.81.35.2', '45.238.224.59', '80.79.48.188', '45.227.78.11', '136.169.220.34', '186.224.33.11', '41.190.93.207', '168.121.112.11', '111.11.11.178', '170.79.188.19', '80.251.195.74', '186.192.79.214', '45.234.48.131', '213.87.70.131', '176.104.6.65', '177.75.120.12', '157.157.52.10', '187.16.242.8', '190.2.120.2', '186.159.96.134', '41.210.187.3', '38.102.246.2', '185.50.98.41', '185.10.221.255', '212.96.94.70', '45.176.180.82', '131.221.84.18', '103.105.212.178', '177.39.154.142', '46.227.166.106', '138.117.36.200', '189.14.65.20', '83.174.193.181', '79.140.16.5', '15.90.164.21', '85.135.32.101', '103.26.136.4', '189.14.65.19', '213.87.211.34', '51.89.22.77', '154.52.11.166', '93.175.192.47', '156.176.255.165', '177.87.54.5', '45.232.196.28', '193.41.129.15', '185.111.36.210', '154.52.12.103', '93.180.48.33', '45.230.252.67', '193.19.164.86', '195.175.255.48', '91.189.221.38', '185.68.100.114', '186.224.0.18', '148.69.161.209', '160.75.70.18', '177.87.119.214', '205.171.19.238', '131.196.169.10', '45.224.72.15', '102.131.18.2', '177.37.24.21', '195.168.1.140', '2.78.40.20', '186.225.128.231', '103.16.205.190', '213.87.99.152', '187.94.32.10', '164.163.98.19', '197.215.160.26', '217.8.235.145', '8.0.23.12', '111.23.238.162', '106.120.89.196', '14.192.150.226', '45.171.144.42', '85.249.22.249', '112.17.46.27', '45.182.194.50', '213.224.146.11', '195.138.80.165', '45.167.191.15', '213.224.146.37', '194.158.204.238', '213.140.228.190', '46.175.201.14', '146.231.129.102', '61.220.8.184', '150.254.173.2', '194.186.227.196', '186.1.142.7', '102.176.175.67', '194.69.172.67', '203.96.208.138', '180.241.233.253', '177.185.212.236', '45.233.204.255', '194.154.226.178', '196.46.176.250', '62.197.161.242', '213.87.158.72', '83.158.5.32', '45.162.225.30', '160.238.240.4', '213.190.55.25', '213.87.211.35', '185.136.227.228', '217.76.77.42', '109.61.1.129', '112.17.46.26', '154.52.12.110', '185.113.32.146', '45.226.148.98', '89.250.192.101', '211.138.19.91', '8.0.34.7', '80.76.224.18', '202.43.116.50', '192.221.143.9', '158.75.1.5', '203.96.208.59', '187.86.128.83', '213.87.162.171', '112.65.23.123', '85.93.226.10', '177.124.4.253', '177.155.80.1', '170.84.96.5', '196.2.64.15', '93.85.251.5', '180.241.233.32', '138.94.160.166', '200.77.183.229', '154.52.12.105', '45.70.20.2', '91.224.224.44', '123.30.52.142', '213.87.70.136', '168.232.7.30', '80.251.201.58', '58.53.186.94', '89.189.150.2', '83.234.11.203', '170.79.112.12', '168.95.43.167', '58.53.186.66', '45.233.200.7', '195.191.221.66', '192.221.151.4', '202.51.94.8', '81.192.17.90', '45.172.144.55', '41.212.33.101', '201.249.172.74', '85.26.186.169', '200.52.229.2', '191.5.96.10', '200.24.51.171', '143.202.29.235', '195.175.255.142', '80.251.195.73', '185.94.212.2', '154.52.12.104', '77.37.251.75', '203.72.153.154', '177.66.104.78', '154.52.12.116', '83.219.128.15', '91.227.242.253', '202.79.38.36', '202.152.254.253', '202.74.33.155', '177.11.16.77', '41.221.0.20', '202.144.211.169', '103.126.30.77', '185.222.23.245', '131.108.172.106', '181.191.8.68', '202.74.33.156', '31.134.120.4', '83.246.135.100', '47.106.96.109', '183.91.16.70', '103.105.174.2', '118.98.104.140', '168.195.84.18', '41.59.226.88', '202.43.117.50', '101.98.5.194', '156.38.4.202', '186.1.128.8', '77.238.225.254', '221.181.49.188', '187.85.0.95', '217.8.235.146', '218.32.144.1', '193.93.78.110', '187.86.128.82', '168.181.190.41', '202.74.33.131', '62.92.124.19', '213.87.70.137', '66.185.123.249', '101.7.8.187', '149.5.233.20', '45.185.0.5', '83.235.71.103', '213.87.211.43', '217.14.201.15', '176.112.160.21', '203.114.147.178', '144.122.199.93', '196.201.225.19', '201.71.60.3', '191.102.216.47', '84.208.26.23', '58.27.148.1', '213.226.7.35', '211.138.19.83', '188.128.87.242', '213.224.146.59', '222.184.232.92', '91.220.124.28', '213.158.199.11', '200.35.65.54', '37.57.0.210', '202.29.48.52', '61.19.67.254', '193.231.100.35', '84.43.191.220', '195.191.182.3', '45.227.78.13', '177.185.48.3', '185.200.60.11', '154.52.11.161', '8.0.14.142', '213.87.99.137', '45.168.155.50', '91.193.224.3', '200.9.182.5', '185.106.113.47', '212.188.8.5', '186.0.136.3', '91.81.132.99', '61.220.8.115', '61.220.8.23', '188.244.249.2', '189.14.80.247', '195.138.80.138', '168.197.143.249', '93.159.158.18', '194.255.58.234', '171.25.182.27', '210.3.254.5', '193.232.148.72', '162.255.45.243', '195.88.144.7', '213.224.146.58', '185.54.230.10', '86.51.23.186', '77.93.126.195', '41.216.125.180', '178.176.230.208', '46.61.224.37', '41.73.59.8', '217.195.66.253', '61.220.8.33', '8.0.7.13', '45.233.204.254', '45.233.202.6', '45.171.224.15', '203.114.147.186', '148.218.60.1', '81.212.190.16', '186.1.178.35', '150.146.129.249', '193.41.76.14', '186.130.130.85', '94.25.229.16', '80.235.8.196', '172.107.246.98', '213.224.146.2', '5.149.240.11', '189.36.132.3', '128.178.223.25', '37.57.147.161', '177.125.116.5', '192.89.202.26', '18.192.31.75', '94.243.71.147', '31.173.240.176', '18.132.81.11', '196.29.180.26', '185.194.33.40', '170.254.251.11', '61.220.8.158', '212.65.133.207', '132.255.88.22', '212.37.37.51', '194.154.226.179', '177.10.0.214', '85.98.208.226', '213.87.211.39', '147.96.1.9', '213.87.162.52', '213.168.179.137', '45.227.180.222', '177.66.32.44', '41.205.5.117', '185.210.36.5', '185.172.240.120', '161.53.160.3', '112.17.46.195', '36.37.252.94', '58.247.118.227', '210.94.72.25', '195.39.243.252', '195.191.73.33', '131.161.24.99', '176.107.254.8', '115.164.31.138', '201.175.153.207', '121.54.70.132', '83.149.0.86', '77.37.251.79', '181.30.140.203', '210.2.185.54', '163.22.2.1', '187.109.17.2', '213.55.128.139', '83.142.142.142', '221.239.30.37', '177.128.52.248', '80.235.1.36', '156.54.175.102', '83.158.8.137', '61.220.9.65', '109.169.34.6', '213.168.179.139', '94.143.52.3', '170.247.76.218', '178.155.7.54', '200.24.51.167', '112.64.143.98', '45.179.48.77', '177.67.56.62', '202.74.33.137', '8.0.41.3', '144.214.2.36', '95.128.184.3', '212.65.135.151']

overlapping_resolvers = set()

one_count = 0
zero_count = 0

def make_arr(resolver_ip_to_verdict_list, ttl, ip_hash_to_asn):
    global one_count
    global zero_count

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

        rat = (bad_len / (good_len + bad_len))
        # "1"
        if ttl == "1":
            if rat >= 1:
                one_count += 1
            elif rat <= 0:
                zero_count += 1

        if rat >= 1:
            if resolver_ip in dnssec_invalidating_resolvers:
                overlapping_resolvers.add(resolver_ip)

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

    # print_meta(arr_global_local, ttl, "local")
    # print_meta(arr_global_public, ttl, "public")

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

    print("Overlapping {}".format(len(overlapping_resolvers)))

    print("One: {}, Zero: {}".format(one_count, zero_count))

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
    # geographic_exitnode_fraction()
    # table_maker_v2()
    # analyzed_table = time.time()
    # print("Analyze table {}".format((analyzed_table - start_time) / 60))
    # geographic_correct_incorrect_distribution_all_over()
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

# init()

# get_client_to_country_distro()