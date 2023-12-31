'''
How many dishonoring ips we could reach with Proxyrack ??

How many of them are proved to be dishonoring ??

Why are they dishonoring?? min ttl? ttl settings ??
'''

import json

'''
    Local dishonoring: 1,0,0,0,0,0,0,0,1,3,58
    Public dishonring: 0,0,0,0,0,0,0,6,2,9,64
'''

def get_dishonoring_ori_set():
    f = open("dishonor_data.json")
    data = json.load(f)['ttl_to_dishonoring_resolvers']
    ans = set()
    for ttl in data:
        for element in data[ttl]:
            ans.add(element[0])
    return list(ans)


def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files


def get_all_resolvers():
    f = open("1_min_resolvers.json")
    data = json.load(f)["1"]
    a = []
    for tup in data:
        a.append(tup[0])
    return a


def get_pub_loc_dict():
    f = open("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/graph_data_pre_v_32/resolver_to_publoc.json")
    data = json.load(f)
    return data


def get_ratio_dict():
    f = open("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/graph_data_pre_v_32/resolver_to_ratio.json")
    data = json.load(f)
    return data


def analyze_files(files, resolver_to_is_dishonor_vote, flag, ttl_list, reached_by_direct_probing, is_true=True):
    for file in files:
        f = open(file)
        d = json.load(f)

        for req_id in d:
            try:
                ttl_1 = d[req_id]["ttl_1"]

                if is_true:
                    tp = d[req_id]['tuple']
                    resolver = tp[0]
                else:
                    resolver = d[req_id]['resolver']

                ttl_2 = d[req_id]["ttl_2"]
                ip_1 = d[req_id]["ip_1"]
                ip_2 = d[req_id]["ip_2"]
                # t_1 = d[req_id]['timestamp_1']
                # t_2 = d[req_id]['timestamp_2']
                # time_def = t_2 - t_1

                if ttl_1 > 60:
                    ttl_list.append(ttl_1)

                if ip_1 != '52.44.221.99':
                    continue

                if ttl_1 > 60 or ip_2 == '52.44.221.99':
                    if flag == 2:
                        reached_by_direct_probing[resolver] = True
                    resolver_to_is_dishonor_vote[resolver] = False
                else:
                    # 1610/1621
                    if flag == 2:
                        reached_by_direct_probing[resolver] = True
                    if resolver not in resolver_to_is_dishonor_vote:
                        resolver_to_is_dishonor_vote[resolver] = True
            except Exception as e:
                pass


def get_resolver_to_dishonor_dict():
    proxy_rack_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_v3/")
    direct_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_direct_v3/")

    from collections import defaultdict
    resolver_to_is_dishonor_vote = {}

    analyze_files(proxy_rack_dump_files, resolver_to_is_dishonor_vote, 1)
    analyze_files(direct_dump_files, resolver_to_is_dishonor_vote, 2)

    return resolver_to_is_dishonor_vote



def get_resolver_to_dishonor_dict_v3(str):
    ttl_list = []

    # is_True = True
    # direct_dump_files = get_files_from_dir("cross_check_direct_v21/{}/".format(str))
    # proxy_rack_dump_files = get_files_from_dir("cross_check_v21/{}/".format(str))

    is_True = False
    direct_dump_files = ["data/honor_direct.json"]
    proxy_rack_dump_files = ["data/honor_proxy.json"]

    from collections import defaultdict
    resolver_to_is_dishonor_vote = {}

    reached_by_direct_probing = defaultdict(lambda: False)

    analyze_files(proxy_rack_dump_files, resolver_to_is_dishonor_vote, 1, ttl_list, reached_by_direct_probing, is_true=is_True)
    analyze_files(direct_dump_files, resolver_to_is_dishonor_vote, 2, ttl_list, reached_by_direct_probing, is_true=is_True)

    return resolver_to_is_dishonor_vote, ttl_list, reached_by_direct_probing


def get_resolver_to_dishonor_dict_v2(str):
    ttl_list = []

    # is_True = True
    # direct_dump_files = get_files_from_dir("cross_check_direct_v21/{}/".format(str))
    # proxy_rack_dump_files = get_files_from_dir("cross_check_v21/{}/".format(str))

    is_True = False
    direct_dump_files = ["proxy-direct-dump/dishonor_direct.json"]
    proxy_rack_dump_files = ["proxy-direct-dump/dishonor_proxy.json"]

    # f = open("data/dishonor_direct.json")
    # dishonor_dd = json.load(f)
    #
    # f = open("data/dishonor_proxy.json")
    # dishonor_pxy = json.load(f)

    from collections import defaultdict
    resolver_to_is_dishonor_vote = {}

    reached_by_direct_probing = defaultdict(lambda: False)

    analyze_files(proxy_rack_dump_files, resolver_to_is_dishonor_vote, 1, ttl_list, reached_by_direct_probing, is_true=is_True)
    analyze_files(direct_dump_files, resolver_to_is_dishonor_vote, 2, ttl_list, reached_by_direct_probing, is_true=is_True)

    return resolver_to_is_dishonor_vote, ttl_list, reached_by_direct_probing


def get_chaos_files():
    resolver_to_chaos = {}
    proxy_rack_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/proxyRack/phrarh/cross_check_v6/")
    #direct_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_direct_v3/")

    from collections import defaultdict

    for file in proxy_rack_dump_files:
        f = open(file)
        d = json.load(f)
        for key in d:
            resolver_to_chaos[key] = d[key][1: -1]
    return resolver_to_chaos


def sanity_checker(resolver_to_dishonor_dict, ratio_dict):
    for key in resolver_to_dishonor_dict:
        s = set()
        for element in resolver_to_dishonor_dict[key]:
            s.add(element[0])
        if len(s) > 1:
            print(key, resolver_to_dishonor_dict[key], "-->", ratio_dict[key])


def entry_v2(str):
    resolver_to_dishonor_dict, ttl_list, reached_by_direct_probing_dict = get_resolver_to_dishonor_dict_v2(str)

    dis, hon = 0, 0
    hon_public, dis_public = 0, 0
    hon_local, dis_local = 0, 0

    f = open("data/1_duo.json")
    bd = json.load(f)
    d_honor_mini = bd['corr_set']
    d_dishonor_mini = bd['inc_set']

    # p = get_chaos_files()
    from collections import defaultdict

    t_ip_set = set()
    d = d_honor_mini
    a = 1
    for e in d_dishonor_mini:
        ip = e
        if ip in resolver_to_dishonor_dict:
            if resolver_to_dishonor_dict[ip] is True:
                hon += 1
                if reached_by_direct_probing_dict[ip]:
                    hon_public += 1
                else:
                    hon_local += 1
                    print(ip)
                    t_ip_set.add(ip)
            else:
                dis += 1
                if reached_by_direct_probing_dict[ip]:
                    dis_public += 1
                else:
                    dis_local += 1

    # with open("data/t_ip_set.json", "w") as ouf:
    #     json.dump(list(t_ip_set), fp=ouf)
    print("{} : Total target {}, Reached {}, Dishonor {}, Honor {}".format(str, len(d), dis + hon, dis, hon))
    print("Dishonor  public {}, Honor public {}, Dishonor local {}, Honor local {}".format(dis_public, hon_public, dis_local, hon_local))


entry_v2("dishonor")


def entry_v3():
    resolver_to_dishonor_dict = get_resolver_to_dishonor_dict_v2()
    f = open("yo.json")
    d = json.load(f)
    z_inc, z_cor, o_inc, o_cor = 0, 0, 0, 0

    # p = get_chaos_files()
    from collections import defaultdict


    dd = {
        2: {
            "tot": 0,
            "found": 0,
            "inc": 0
        },
        4: {
            "tot": 0,
            "found": 0,
            "inc": 0
        },
        -1: {
            "tot": 0,
            "found": 0,
            "inc": 0
        }
    }


    for e in d:
        ip, ratio = e[0], e[1]
        is_dishonor = -1

        if ip in resolver_to_dishonor_dict:
            if resolver_to_dishonor_dict[ip] is True:
                is_dishonor = False
            else:
                is_dishonor = True

        index = 0

        if ratio <= .2:
            index = 2
        elif .2 < ratio <= .4:
            index = 4
        else:
            index = -1

        dd[index]["tot"] += 1
        if is_dishonor != -1:
            dd[index]["found"] += 1
            if is_dishonor:
                dd[index]["inc"] += 1




    a = 1


def entry():
    skip_list = ["194.31.155.4", "91.217.4.9"]
    resolvers = get_all_resolvers()
    pub_loc_dict = get_pub_loc_dict()
    ratio_dict = get_ratio_dict()
    resolver_to_dishonor_dict = get_resolver_to_dishonor_dict()

    lst = [0, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1]

    from collections import defaultdict
    bucket_to_total_count = defaultdict(lambda: 0)
    bucket_to_detected_count = defaultdict(lambda: 0)
    bucket_to_dishonoring_count = defaultdict(lambda: 0)

    f = open("resolver_to_asn.json")
    resolver_to_asn = json.load(f)

    dict_counter = defaultdict(lambda : 0)
    bad_set = list()

    detected_in_proxy_rack = 0
    for resolver in resolvers:
        if not (pub_loc_dict[resolver] is True):
            continue

        if resolver in skip_list:
            continue
        ratio = ratio_dict[resolver]
        ratio_bucket = int(ratio * 10)
        bucket_to_total_count[ratio_bucket] += 1
        if resolver in resolver_to_dishonor_dict:
            detected_in_proxy_rack += 1

            bucket_to_detected_count[ratio_bucket] += 1
            if resolver_to_dishonor_dict[resolver] is False:
                bucket_to_dishonoring_count[ratio_bucket] += 1
                dict_counter[resolver_to_asn[resolver]] += 1
            elif ratio_bucket == 9:
                a = 1
                bad_set.append(resolver_to_asn[resolver])

    a = 1
    # local -> both ips belong to 27665,
    # public -> 3 4134, 29286

# entry_v2("honor")

def get_min_ttl():
    global_dishonoring_resolver_list = get_dishonoring_ori_set()

    dump_files = get_files_from_dir("cross_check")

    reachable_ips = set()
    cross_checked_dishonoring_ips = set()
    momin = set()

    '''
        min-ttl
        ttl good: increase
        ttl good: static
        ttl good: wrong decrease
        ttl good: ttl 0

    '''
    min_ttl_vis = {}
    min_ttl_cnt = list()
    min_ttl_set = set()
    ttl_increase = set()
    ttl_decrease = set()
    ttl_same = set()
    ttl_zero = set()

    for file in dump_files:
        f = open("cross_check/{}".format(file))
        d = json.load(f)

        # dishonor case: ip2 = ! ip_2 or ttl != 60
        # abnormal case: ttl < 60, (ttl == 60 but ip2 = ! ip_2)

        for req_id in d:
            try:
                temp = d[req_id]
                ttl_1 = d[req_id]["ttl_1"]
                resolver = d[req_id]['tuple'][0]

                ttl_2 = d[req_id]["ttl_2"]
                ip_1 = d[req_id]["ip_1"]
                ip_2 = d[req_id]["ip_2"]
                t_1 = d[req_id]['timestamp_1']
                t_2 = d[req_id]['timestamp_2']
                time_def = t_2 - t_1

                if resolver not in global_dishonoring_resolver_list:
                    continue

                reachable_ips.add(resolver)
                if ttl_1 > 60 or ip_2 == '52.44.221.99':
                    '''
                        min-ttl
                        ttl good: increase
                        ttl good: static
                        ttl good: wrong decrease
                        ttl good: ttl 0

                        min_ttl_vis = {}
                        min_ttl_cnt = list()

                        min_ttl_set = set()
                        ttl_increase = set()
                        ttl_decrease = set()
                        ttl_zero = set()
                        ttl_same = set()

                    '''
                    if ttl_1 > 60:
                        min_ttl_set.add(resolver)
                        if resolver not in min_ttl_vis:
                            min_ttl_vis[resolver] = 1
                            min_ttl_cnt.append(ttl_1)
                    else:
                        if ttl_2 > ttl_1:
                            ttl_increase.add(resolver)
                        elif ttl_2 < ttl_1 and ttl_2 != 0:
                            ttl_decrease.add(resolver)
                        elif ttl_2 == 0:
                            ttl_zero.add(resolver)
                        elif ttl_2 == ttl_1 == 60:
                            ttl_same.add(resolver)

                    cross_checked_dishonoring_ips.add(resolver)

            except:
                pass
    min_ttl_cnt.sort()
    a = 1

    with open("data/min_ttl_list.json", "w") as ouf:
        json.dump(min_ttl_cnt, fp=ouf)

def unknown():
    global_dishonoring_resolver_list = get_dishonoring_ori_set()

    dump_files = get_files_from_dir("cross_check")

    reachable_ips = set()
    cross_checked_dishonoring_ips = set()
    momin = set()

    '''
        min-ttl
        ttl good: increase
        ttl good: static
        ttl good: wrong decrease
        ttl good: ttl 0

    '''
    min_ttl_vis = {}
    min_ttl_cnt = list()
    min_ttl_set = set()
    ttl_increase = set()
    ttl_decrease = set()
    ttl_same = set()
    ttl_zero = set()

    for file in dump_files:
        f = open("cross_check/{}".format(file))
        d = json.load(f)

        # dishonor case: ip2 = ! ip_2 or ttl != 60
        # abnormal case: ttl < 60, (ttl == 60 but ip2 = ! ip_2)

        for req_id in d:
            try:
                temp = d[req_id]
                ttl_1 = d[req_id]["ttl_1"]
                resolver = d[req_id]['tuple'][0]

                ttl_2 = d[req_id]["ttl_2"]
                ip_1 = d[req_id]["ip_1"]
                ip_2 = d[req_id]["ip_2"]
                t_1 = d[req_id]['timestamp_1']
                t_2 = d[req_id]['timestamp_2']
                time_def = t_2 - t_1

                if resolver not in global_dishonoring_resolver_list:
                    continue

                reachable_ips.add(resolver)
                if ttl_1 > 60 or ip_2 == '52.44.221.99':
                    '''
                        min-ttl
                        ttl good: increase
                        ttl good: static
                        ttl good: wrong decrease
                        ttl good: ttl 0

                        min_ttl_vis = {}
                        min_ttl_cnt = list()

                        min_ttl_set = set()
                        ttl_increase = set()
                        ttl_decrease = set()
                        ttl_zero = set()
                        ttl_same = set()

                    '''
                    if ttl_1 > 60:
                        min_ttl_set.add(resolver)
                        if resolver not in min_ttl_vis:
                            min_ttl_vis[resolver] = 1
                            min_ttl_cnt.append(ttl_1)
                    else:
                        if ttl_2 > ttl_1:
                            ttl_increase.add(resolver)
                        elif ttl_2 < ttl_1 and ttl_2 != 0:
                            ttl_decrease.add(resolver)
                        elif ttl_2 == 0:
                            ttl_zero.add(resolver)
                        elif ttl_2 == ttl_1 == 60:
                            ttl_same.add(resolver)

                    cross_checked_dishonoring_ips.add(resolver)

            except:
                pass
    min_ttl_cnt.sort()
    a = 1

    with open("data/min_ttl_list.json", "w") as ouf:
        json.dump(min_ttl_cnt, fp=ouf)