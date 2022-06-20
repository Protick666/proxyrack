'''

How many dishonoring ips we could reach with Proxyrack ??

How many of them are proved to be dishonoring ??

Why are they dishonoring?? min ttl? ttl settings ??

'''

import json

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
    onlyfiles = [f for f in listdir(path) if isfile(join(path, f))]
    return onlyfiles


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

with open("min_ttl_list.json", "w") as ouf:
    json.dump(min_ttl_cnt, fp=ouf)