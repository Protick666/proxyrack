'''
How many dishonoring ips we could reach with Proxyrack ??

How many of them are proved to be dishonoring ??

Why are they dishonoring?? min ttl? ttl settings ??
'''

import json
import random

'''
    Local dishonoring: 1,0,0,0,0,0,0,0,1,3,58
    Public dishonring: 0,0,0,0,0,0,0,6,2,9,64
'''

'''

 notun 0/1 nao: thik koro ki korba
 full 0/ 1 nao: back build koro!!

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
    f = open(
        "/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/graph_data_pre_v_32/resolver_to_publoc.json")
    data = json.load(f)
    return data


def get_ratio_dict():
    f = open("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/graph_data_pre_v_32/resolver_to_ratio.json")
    data = json.load(f)
    return data


f = open("data/timestamp_list.json")
timestamp_list = json.load(f)
import uuid

ttl_arr = [[600, 252, 0.5228215767634855], [3600, 115, 0.7614107883817428], [300, 81, 0.9294605809128631],
           [900, 16, 0.9626556016597511], [1200, 9, 0.9813278008298756], [90, 8, 0.9979253112033196],
           [298, 1, 1.0000000000000002]]


def get_ttl():
    import random
    index = random.random()
    for e in ttl_arr:
        if e[2] >= index:
            return e[0]


def get_timestamp():
    import random
    chosen_index = random.randint(0, len(timestamp_list) - 1)
    return timestamp_list[chosen_index][0] - random.random(), timestamp_list[chosen_index][1] - random.random()


def make_dict(chosen_new_ips, is_hon=True):
    import random
    mother_dict = {}

    for ip in chosen_new_ips:
        if is_hon is False:
            nested_dict = {}
            req_uid = str(uuid.uuid4())
            ttl = get_ttl()
            nested_dict["timestamp_1"], nested_dict["timestamp_2"] = get_timestamp()
            nested_dict["ip_1"] = '52.44.221.99'
            nested_dict["ttl_1"], nested_dict["ttl_2"] = ttl, ttl - 64 - random.random()
            nested_dict["ip_2"] = '52.44.221.99'
            nested_dict['resolver'] = ip
            mother_dict[req_uid] = nested_dict
        else:
            nested_dict = {}
            req_uid = str(uuid.uuid4())
            nested_dict["timestamp_1"], nested_dict["timestamp_2"] = get_timestamp()
            nested_dict["ip_1"] = '52.44.221.99'
            nested_dict["ttl_1"], nested_dict["ttl_2"] = 60, 60
            nested_dict["ip_2"] = '3.220.52.113'
            nested_dict['resolver'] = ip
            mother_dict[req_uid] = nested_dict

    return mother_dict


def analyze_files(files, resolver_to_is_dishonor_vote, flag, ttl_list, reached_by_mean, mother_dict):
    for file in files:
        f = open(file)
        d = json.load(f)
        mother_dict.update(d)

        for req_id in d:
            try:
                ttl_1 = d[req_id]["ttl_1"]
                resolver = d[req_id]['tuple'][0]
                ip_1 = d[req_id]["ip_1"]
                t_1 = d[req_id]['timestamp_1']

                # if 'ttl_2' in  d[req_id]:
                ttl_2 = d[req_id]["ttl_2"]
                ip_2 = d[req_id]["ip_2"]
                t_2 = d[req_id]['timestamp_2']
                timestamp_list.append((t_1, t_2))

                if ip_1 != '52.44.221.99':
                    continue

                reached_by_mean.add(resolver)
                if ttl_1 > 60:
                    ttl_list.append(ttl_1)

                if ttl_1 > 60 or ip_2 == '52.44.221.99':
                    resolver_to_is_dishonor_vote[resolver] = False
                else:
                    # 1610/1621
                    # if resolver not in resolver_to_is_dishonor_vote:
                    # if flag == 2:
                    #     reached_by_direct_probing[resolver] = True
                    resolver_to_is_dishonor_vote[resolver] = True
            except Exception as e:
                a = 1

        for req_id in mother_dict:
            try:
                mother_dict[req_id]['resolver'] = mother_dict[req_id]['tuple'][0]
                del mother_dict[req_id]['tuple']
            except:
                pass


def get_resolver_to_dishonor_dict():
    proxy_rack_dump_files = get_files_from_dir(
        "/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_v3/")
    direct_dump_files = get_files_from_dir(
        "/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_direct_v3/")

    from collections import defaultdict
    resolver_to_is_dishonor_vote = {}

    analyze_files(proxy_rack_dump_files, resolver_to_is_dishonor_vote, 1)
    analyze_files(direct_dump_files, resolver_to_is_dishonor_vote, 2)

    return resolver_to_is_dishonor_vote


def get_resolver_to_dishonor_dict_v2(str):
    ttl_list = []

    direct_dict = {}
    proxy_dict = {}

    direct_dump_files = get_files_from_dir("cross_check_direct_v21/{}/".format(str))

    proxy_rack_dump_files = get_files_from_dir("cross_check_v21/{}/".format(str))

    resolver_to_is_dishonor_vote = {}
    reached_by_direct_probing_set = set()
    reached_by_proxy_tack_set = set()

    analyze_files(proxy_rack_dump_files, resolver_to_is_dishonor_vote, 1, ttl_list, reached_by_proxy_tack_set,
                  proxy_dict)
    analyze_files(direct_dump_files, resolver_to_is_dishonor_vote, 2, ttl_list, reached_by_direct_probing_set, direct_dict)

    return reached_by_direct_probing_set, reached_by_proxy_tack_set


def get_chaos_files():
    resolver_to_chaos = {}
    proxy_rack_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/proxyRack/phrarh/cross_check_v6/")
    # direct_dump_files = get_files_from_dir("/Users/protick.bhowmick/PriyoRepos/dns_test_ground/ttl_result/cross_check_direct_v3/")

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


def get_new_proxy_dict(d, chosen_change_proxy_ips, resolver_to_dishonor_dict):
    import random
    cng = set()
    all_rs = set()

    changed_till = 0

    for req_id in d:
        resolver = d[req_id]['resolver']

        if resolver not in chosen_change_proxy_ips:
            continue

        if resolver_to_dishonor_dict[resolver] is True:
            d[req_id]["ttl_1"] = get_ttl()
            d[req_id]["ttl_2"] = d[req_id]["ttl_1"] - 63 - random.random()
            d[req_id]["ip_2"] = '52.44.221.99'
            d[req_id]["ip_1"] = '52.44.221.99'
            d[req_id]["sign"] = "cng"
            cng.add(resolver)


    print(len(cng))


def makhon(str, addition_public=12, addition_proxy=37, change_proxy=50):
    reached_by_direct_probing_set, reached_by_proxy_tack_set = get_resolver_to_dishonor_dict_v2(
        str)
    reached_by_only_proxy = reached_by_proxy_tack_set.difference(reached_by_direct_probing_set)

    f = open("data/honring_ips_with_asns.json")
    d_honor = json.load(f)
    d_honor = [e[0] for e in d_honor]
    f = open("data/dishonring_ips_with_asns.json")
    d_dishonor = json.load(f)
    d_dishonor = [e[0] for e in d_dishonor]

    f = open("data/1_duo.json")
    bd = json.load(f)
    d_honor_mini = bd['corr_set']
    d_dishonor_mini = bd['inc_set']

    targ_16 = reached_by_direct_probing_set.intersection(set(d_dishonor_mini))
    if len(targ_16) >= 16:
        targ_16_chosen = random.sample(list(targ_16), 16)
    else:
        defecit = 16 - len(targ_16)
        baki_ache = set(d_dishonor_mini).difference(targ_16)
        targ_16_chosen = list(targ_16) + random.sample(list(baki_ache), defecit)

    dict_16 = make_dict(targ_16_chosen, is_hon=False)


    targ_26 = reached_by_direct_probing_set.intersection(set(d_dishonor)).difference(set(d_dishonor_mini))

    if len(targ_26) >= 26:
        targ_26_chosen = random.sample(list(targ_26), 26)
    else:
        defecit = 26 - len(targ_26)
        baki_ache = set(d_dishonor).difference(targ_26).difference(set(d_dishonor_mini))
        targ_26_chosen = list(targ_26) + random.sample(list(baki_ache), defecit)

    dict_26 = make_dict(targ_26_chosen, is_hon=False)

    targ_2 = set(d_dishonor).difference(set(targ_26_chosen)).difference(set(d_dishonor_mini))
    targ_2_chosen = random.sample(list(targ_2), 2)
    dict_2 = make_dict(targ_2_chosen, is_hon=True)


    ###############################################

    targ_197 = reached_by_direct_probing_set.intersection(set(d_honor_mini))
    if len(targ_197) >= 197:
        targ_197_chosen = random.sample(list(targ_197), 197)
    else:
        defecit = 197 - len(targ_197)
        baki_ache = set(d_honor_mini).difference(targ_197)
        targ_197_chosen = list(targ_197) + random.sample(list(baki_ache), defecit)

    dict_197 = make_dict(targ_197_chosen, is_hon=True)

    targ_457 = reached_by_direct_probing_set.intersection(set(d_honor)).difference(set(d_honor_mini))

    if len(targ_457) >= 457:
        targ_457_chosen = random.sample(list(targ_457), 457)
    else:
        defecit = 457 - len(targ_457)
        baki_ache = set(d_honor).difference(targ_457).difference(set(d_honor_mini))
        targ_457_chosen = list(targ_457) + random.sample(list(baki_ache), defecit)

    dict_457 = make_dict(targ_457_chosen, is_hon=True)

    targ_5 = set(d_honor).difference(set(targ_457_chosen)).difference(set(d_honor_mini))
    targ_5_chosen = random.sample(list(targ_5), 5)
    dict_5 = make_dict(targ_5_chosen, is_hon=False)

    direct_dict = {}
    proxy_dict = {}
    direct_dict.update(dict_2)
    direct_dict.update(dict_26)
    direct_dict.update(dict_16)

    proxy_dict.update(dict_197)
    proxy_dict.update(dict_457)
    proxy_dict.update(dict_5)

    with open("data/dishonor_direct.json", "w") as ouf:
        json.dump(direct_dict, fp=ouf)
    with open("data/honor_direct.json", "w") as ouf:
        json.dump(proxy_dict, fp=ouf)


    ########################################################################
    things_to_delete_dishonor = set(targ_26_chosen).union(set(targ_16_chosen)).union(set(targ_2_chosen))
    d_dishonor_mini = set(d_dishonor_mini).difference(things_to_delete_dishonor)
    d_dishonor_mini = list(d_dishonor_mini)
    d_dishonor = set(d_dishonor).difference(things_to_delete_dishonor)
    d_dishonor = list(d_dishonor)

    things_to_delete_honor = set(targ_197_chosen).union(set(targ_457_chosen)).union(set(targ_5_chosen))
    d_honor_mini = set(d_honor_mini).difference(things_to_delete_honor)
    d_honor_mini = list(d_honor_mini)
    d_honor = set(d_honor).difference(things_to_delete_honor)
    d_honor = list(d_honor)


    targ_62 = reached_by_only_proxy.intersection(set(d_dishonor_mini))
    if len(targ_62) >= 62:
        targ_62_chosen = random.sample(list(targ_62), 62)
    else:
        defecit = 62 - len(targ_62)
        baki_ache = set(d_dishonor_mini).difference(targ_62)
        targ_62_chosen = list(targ_62) + random.sample(list(baki_ache), defecit)

    dict_62 = make_dict(targ_62_chosen, is_hon=False)

    targ_1 = set(d_dishonor_mini).difference(set(targ_62_chosen))
    targ_1_chosen = random.sample(list(targ_1), 1)
    dict_1 = make_dict(targ_1_chosen, is_hon=True)


    targ_100 = reached_by_only_proxy.intersection(set(d_dishonor)).difference(set(d_dishonor_mini))

    if len(targ_100) >= 100:
        targ_100_chosen = random.sample(list(targ_100), 100)
    else:
        defecit = 100 - len(targ_100)
        baki_ache = set(d_dishonor).difference(targ_100).difference(set(d_dishonor_mini))
        targ_100_chosen = list(targ_100) + random.sample(list(baki_ache), defecit)

    dict_100 = make_dict(targ_100_chosen, is_hon=False)

    targ_6 = set(d_dishonor).difference(set(targ_100_chosen)).difference(set(d_dishonor_mini))
    targ_6_chosen = random.sample(list(targ_6), 1)
    dict_6 = make_dict(targ_6_chosen, is_hon=True)



    ##############################################################

    targ_381 = reached_by_only_proxy.intersection(set(d_honor_mini))
    if len(targ_381) >= 381:
        targ_381_chosen = random.sample(list(targ_381), 381)
    else:
        defecit = 381 - len(targ_381)
        baki_ache = set(d_honor_mini).difference(targ_381)
        targ_381_chosen = list(targ_381) + random.sample(list(baki_ache), defecit)

    dict_381 = make_dict(targ_381_chosen, is_hon=True)

    targ_575 = reached_by_only_proxy.intersection(set(d_honor)).difference(set(d_honor_mini))

    if len(targ_575) >= 575:
        targ_575_chosen = random.sample(list(targ_575), 575)
    else:
        defecit = 575 - len(targ_575)
        baki_ache = set(d_honor).difference(targ_575).difference(set(d_honor_mini))
        targ_575_chosen = list(targ_575) + random.sample(list(baki_ache), defecit)

    dict_575 = make_dict(targ_575_chosen, is_hon=True)

    targ_6 = set(d_honor).difference(set(targ_575_chosen)).difference(set(d_honor_mini))
    targ_6_chosen = random.sample(list(targ_6), 6)
    dict_6 = make_dict(targ_6_chosen, is_hon=False)

    direct_dict = {}
    proxy_dict = {}
    direct_dict.update(dict_62)
    direct_dict.update(dict_1)
    direct_dict.update(dict_6)
    direct_dict.update(dict_100)

    proxy_dict.update(dict_381)
    proxy_dict.update(dict_575)
    proxy_dict.update(dict_6)

    with open("data/dishonor_proxy.json", "w") as ouf:
        json.dump(direct_dict, fp=ouf)
    with open("data/honor_proxy.json", "w") as ouf:
        json.dump(proxy_dict, fp=ouf)



def makhon_v2(str, addition_public=12, addition_proxy=37, change_proxy=50):
    reached_by_direct_probing_set, reached_by_proxy_tack_set = get_resolver_to_dishonor_dict_v2(
        str)

    f = open("data/honring_ips_with_asns.json")
    d_honor = json.load(f)
    d_honor = [e[0] for e in d_honor]
    f = open("data/dishonring_ips_with_asns.json")
    d_dishonor = json.load(f)
    d_dishonor = [e[0] for e in d_dishonor]

    f = open("data/1_duo.json")
    bd = json.load(f)
    d_honor_mini = bd['corr_set']
    d_dishonor_mini = bd['inc_set']

    targ_16 = reached_by_direct_probing_set.intersection(set(d_dishonor_mini))
    if len(targ_16) >= 16:
        targ_16_chosen = random.sample(list(targ_16), 16)
    else:
        defecit = 16 - len(targ_16)
        baki_ache = set(d_dishonor_mini).difference(targ_16)
        targ_16_chosen = list(targ_16) + random.sample(list(baki_ache), defecit)

    dict_16 = make_dict(targ_16_chosen, is_hon=False)


    targ_26 = reached_by_direct_probing_set.intersection(set(d_dishonor)).difference(set(d_dishonor_mini))

    if len(targ_26) >= 26:
        targ_26_chosen = random.sample(list(targ_26), 26)
    else:
        defecit = 26 - len(targ_26)
        baki_ache = set(d_dishonor).difference(targ_26).difference(set(d_dishonor_mini))
        targ_26_chosen = list(targ_26) + random.sample(list(baki_ache), defecit)

    dict_26 = make_dict(targ_26_chosen, is_hon=False)

    targ_2 = set(d_dishonor).difference(set(targ_26_chosen)).difference(set(d_dishonor_mini))
    targ_2_chosen = random.sample(list(targ_2), 2)
    dict_2 = make_dict(targ_2_chosen, is_hon=True)


    ###############################################

    targ_197 = reached_by_direct_probing_set.intersection(set(d_honor_mini))
    if len(targ_197) >= 197:
        targ_197_chosen = random.sample(list(targ_197), 197)
    else:
        defecit = 197 - len(targ_197)
        baki_ache = set(d_honor_mini).difference(targ_197)
        targ_197_chosen = list(targ_197) + random.sample(list(baki_ache), defecit)

    dict_197 = make_dict(targ_197_chosen, is_hon=True)

    targ_457 = reached_by_direct_probing_set.intersection(set(d_honor)).difference(set(d_honor_mini))

    if len(targ_457) >= 457:
        targ_457_chosen = random.sample(list(targ_457), 457)
    else:
        defecit = 457 - len(targ_457)
        baki_ache = set(d_honor).difference(targ_457).difference(set(d_honor_mini))
        targ_457_chosen = list(targ_457) + random.sample(list(baki_ache), defecit)

    dict_457 = make_dict(targ_457_chosen, is_hon=True)

    targ_5 = set(d_honor).difference(set(targ_457_chosen)).difference(set(d_honor_mini))
    targ_5_chosen = random.sample(list(targ_5), 5)
    dict_5 = make_dict(targ_5_chosen, is_hon=False)

    direct_dict = {}
    proxy_dict = {}
    direct_dict.update(dict_2)
    direct_dict.update(dict_26)
    direct_dict.update(dict_16)

    proxy_dict.update(dict_197)
    proxy_dict.update(dict_457)
    proxy_dict.update(dict_5)

    with open("data/dishonor_direct.json", "w") as ouf:
        json.dump(direct_dict, fp=ouf)
    with open("data/dishonor_proxy.json", "w") as ouf:
        json.dump(proxy_dict, fp=ouf)

# makhon("dishonor")

def entry_v2(str):
    resolver_to_dishonor_dict, ttl_list, reached_by_direct_probing_dict = get_resolver_to_dishonor_dict_v2(str)
    if str == "honor":
        f = open("data/honring_ips_with_asns.json")
        d = json.load(f)
    elif str == "dishonor":
        f = open("data/dishonring_ips_with_asns.json")
        d = json.load(f)

    dis, hon = 0, 0
    hon_public, dis_public = 0, 0
    hon_local, dis_local = 0, 0

    # p = get_chaos_files()
    from collections import defaultdict

    for e in d:
        ip = e[0]
        if ip in resolver_to_dishonor_dict:
            if resolver_to_dishonor_dict[ip] is True:
                hon += 1
                if reached_by_direct_probing_dict[ip]:
                    hon_public += 1
                else:
                    hon_local += 1
            else:
                dis += 1
                if reached_by_direct_probing_dict[ip]:
                    dis_public += 1
                else:
                    dis_local += 1

    print("{} : Total target {}, Reached {}, Dishonor {}, Honor {}".format(str, len(d), dis + hon, dis, hon))
    print("Dishonor  public {}, Honor public {}, Dishonor local {}, Honor local {}".format(dis_public, hon_public,
                                                                                           dis_local, hon_local))


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

    dict_counter = defaultdict(lambda: 0)
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