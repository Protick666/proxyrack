import json

dump_directory = "proxy-direct-dump"

def proc(p):
    d = p.copy()
    for req_id in d:
        del d[req_id]['timestamp_1']
        del d[req_id]['timestamp_2']
    return d

f = open("data/dishonor_direct.json")
dishonor_direct = json.load(f)
dishonor_direct_c = proc(dishonor_direct)

with open("{}/dishonor_direct.json".format(dump_directory), "w") as ouf:
    json.dump(dishonor_direct_c, fp=ouf)

f = open("data/dishonor_proxy.json")
dishonor_proxy = json.load(f)
dishonor_proxy_c = proc(dishonor_proxy)

with open("{}/dishonor_proxy.json".format(dump_directory), "w") as ouf:
    json.dump(dishonor_proxy_c, fp=ouf)

f = open("data/honor_proxy.json")
honor_proxy = json.load(f)
honor_proxy_c = proc(honor_proxy)

with open("{}/honor_proxy.json".format(dump_directory), "w") as ouf:
    json.dump(honor_proxy_c, fp=ouf)

f = open("data/honor_direct.json")
honor_direct = json.load(f)
honor_direct_c = proc(honor_direct)

with open("{}/honor_direct.json".format(dump_directory), "w") as ouf:
    json.dump(honor_direct_c, fp=ouf)

