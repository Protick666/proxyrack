import json
import time
from multiprocessing.dummy import Pool as ThreadPool

global_normal_dns_rtt = []

def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


# Rank: 1, Domain: facebook.com, start: 1668757856.9980085
# Rank: 1, Domain: facebook.com, end: 1668757859.3641381
# [start, end, domain, rank]

# docker cp warm_instance:/projects/stresstest/selenium_v2/log/my_log.log /home/protick/proxyrack/ocsp_simulation/warm_log
# docker cp normal_instance:/projects/stresstest/selenium_v2/log/my_log.log /home/protick/proxyrack/ocsp_simulation/normal_log
# docker cp cold_instance:/projects/stresstest/selenium_v2/log/my_log.log /home/protick/proxyrack/ocsp_simulation/cold_log

# docker cp warm_instance:/projects/stresstest/selenium_v2/log/my_log.log /home/protick/proxyrack/ocsp_simulation/normal_log

# (domain_to_start[domain], domain_to_end[domain], domain, domain_to_rank[domain])


def get_rank_main_domain_tuple(range_str, ts):
    global range_to_index
    global index_to_domain_load_time_list

    index = range_to_index[range_str]
    domain_load_time_list = index_to_domain_load_time_list[index]

    i = 0
    j = len(domain_load_time_list) - 1

    while i <= j:
        mid = (i + j) // 2
        if domain_load_time_list[mid][0] <= ts <= domain_load_time_list[mid][1]:
            return (domain_load_time_list[mid][3], domain_load_time_list[mid][2])
        elif domain_load_time_list[mid][0] > ts:
            j = mid - 1
        elif domain_load_time_list[mid][1] < ts:
            i = mid + 1

    return None

    # st, end, domain, rank

    # time_lst.append((domain_to_start[domain], domain_to_end[domain], domain, domain_to_rank[domain]))

ans_list = []

def do_so(tup):
    dir, ind, tot = tup
    print("starting {}".format(dir))
    segments = dir.split("/")
    file_name = segments[-1]
    base_path = dir + "/"
    global ans_list

    fp_to_serial = {}

    for line in open('{}x509.log'.format(base_path), 'r'):
        try:
            d = json.loads(line)
            fp = d['fingerprint']
            serial = d['certificate.serial']
            fp_to_serial[fp] = serial
        except:
            pass

    for line in open('{}ssl.log'.format(base_path), 'r'):
        try:
            d = json.loads(line)
            ts = d['ts']
            server_name = d['server_name']

            if "demdex" in server_name or "mozilla" in server_name:
                continue

            own_cert_fp = d['cert_chain_fps'][0]
            signer_cert_fp = d['cert_chain_fps'][1]
            rank_main_domain_tuple = get_rank_main_domain_tuple(file_name, ts)
            if rank_main_domain_tuple is None:
                continue
            rank, main_domain = rank_main_domain_tuple
            # tls domain, rank, main domain, cert fp, parent cert fp, serial
            ans_list.append((server_name, rank, main_domain, own_cert_fp, signer_cert_fp, fp_to_serial[own_cert_fp]))
        except:
            pass

    print("done with {}/{}".format(ind, tot))


def get_range_to_index():
    d = {}
    a, b = 1, 100
    index = 0
    while a < 1000000:
        d["{}-{}".format(a, b)] = index
        a += 100
        b += 100
        index = (index + 1) % 5

    return d


def get_dirs(path):
    import os
    return [os.path.join(path, name) for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]

def load_time_lst(index):
    time_lst = []
    domain_to_rank = {}
    domain_to_start = {}
    domain_to_end = {}
    # docker cp nsec1:/projects/stresstest/selenium_v2/log/my_log.log 0
    for line in open('log_2/{}/my_log.log'.format(index), 'r'):
        segments = line.split()
        if 'end' in line:
            domain_to_end[segments[-3][0: -1]] = float(segments[-1])
        if 'start' in line:
            domain_to_start[segments[-3][0: -1]] = float(segments[-1])
        domain_to_rank[segments[-3][0: -1]] = int(segments[-5][0: -1])

    for domain in domain_to_rank:
        try:
            time_lst.append((domain_to_start[domain], domain_to_end[domain], domain, domain_to_rank[domain]))
        except:
            pass
    time_lst.sort()
    return time_lst

print("starting exp")
init = time.time()

range_to_index = get_range_to_index()
index_to_domain_load_time_list = {}

for index in range(5):
    domain_load_time_list = load_time_lst(index)
    index_to_domain_load_time_list[index] = domain_load_time_list

directories = get_dirs("/net/data/dns-ttl/pcap/zeek_logs/nsec")
print("Total dir {}".format(len(directories)))
pool = ThreadPool(100)

dir_order = []
ind = 1
for e in directories:
    dir_order.append((e, ind, len(directories)))
    ind += 1

results = pool.map(do_so, dir_order)

pool.close()
pool.join()

# tls domain, rank, main domain, cert fp, parent cert fp, serial
ans_list.sort(key=lambda x: x[1])

print("Ending exp")

with open("data/all_tls_conns.json", "w") as ouf:
    json.dump(ans_list, fp=ouf)

print("Total minutes taken {}".format((time.time() - init) / 60))




