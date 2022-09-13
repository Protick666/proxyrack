
import json

'''

    * Find out -> Total distinct certs in this period

    * Distinct domains it was mapped for -> *

    * All distinct domains -> [serial numbers]

'''


def read_data_as_s(file_name):
    st = str(file_name)
    if len(st) == 1:
        st = "0" + st
    d = open("/net/data/dns-ttl/certstream/x{}".format(st)).read().splitlines()
    return d


def get_data(file_name, filter_by_message_type):
    print("analyzing{}".format(file_name))
    d = read_data_as_s(file_name=file_name)

    print("File loaded {}".format(file_name))
    cert_entries = []
    line_count = 0
    tot_lines = len(d)
    for p in d:
        line_count += 1
        if line_count % 100000000 == 0:
            print("{}/{} - {}".format(line_count, tot_lines, file_name))
        try:
            e = json.loads(p)
            if e['message_type'] != 'certificate_update':
                continue
            serial = e['data']['leaf_cert']['serial_number']
            domains = e['data']['leaf_cert']['all_domains']
            cert_entries.append((serial, domains))
        except Exception as e:
            a = 1
    return cert_entries


def coalesce_files_into_serial_and_domain_names():
    for f_name in range(2, 20):
        try:
            certs = get_data(file_name=f_name, filter_by_message_type=False)
            with open("data_refined/{}.json".format(f_name), "w") as ouf:
                json.dump(certs, fp=ouf)
        except Exception as e:
            print(f_name, e)


def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files


def def_get_certs():
    files = get_files_from_dir("/home/protick/proxyrack/cert_stream/data_refined/")
    certs = []
    for file in files:
        f = open(file)
        d = json.load(f)
        certs = certs + d
        print("processed {}".format(file))
    return certs


def get_anchestors(domain):
    level_segments = domain.split(".")
    anc_list = set()
    # a . b . com
    for i in range(0, len(level_segments) - 1):
        anc = "*." + ".".join(level_segments[i + 1:])
        anc_list.add(anc)
    return list(anc_list)


def analyze_domain_to_cert_mapping():
    all_certs = def_get_certs()
    with open("data_refined/all_certs_compact.json", "w") as ouf:
        json.dump(all_certs, fp=ouf)

    from collections import defaultdict

    serial_to_domains = defaultdict(lambda: set())
    domain_list = []
    domain_set = set()
    domain_to_serials = defaultdict(lambda: set())
    serials = set()
    for e in all_certs:
        serial = e[0]
        serials.add(serial)
        domains = e[1]
        serial_to_domains[serial].update(set(domains))
        domain_set.update(domains)
        for domain in domains:
            domain_to_serials[domain].add(serial)

    for domain in domain_set:
        level_segments = domain.split(".")
        levels = len(level_segments)
        fld = level_segments[0]
        flag = 1
        if fld == "*":
            flag = 0
        # TODO check sort
        domain_list.append((levels, flag, domain))

    domain_list.sort()

    '''
        *.domain.com -> a, b, c
        a.domain.com -> d, a, b, c
        
    '''

    domain_to_final_serials = defaultdict(lambda: set())

    for e in domain_list:
        _, _, domain = e
        domain_to_final_serials[domain].update(domain_to_serials[domain])
        ancestors = get_anchestors(domain)
        for ancestor in ancestors:
            if ancestor in domain_to_serials:
                domain_to_final_serials[domain].update(domain_to_serials[ancestor])

    domain_to_final_serial_list = defaultdict(lambda: list())
    tot = 0
    for domain in domain_to_final_serials:
        domain_to_final_serial_list[domain] = list(domain_to_final_serials[domain])
        if len(domain_to_final_serial_list[domain]) > 1:
            tot += 1
    print("Total Certs {}".format(len(serials)))
    print("Total domains {}".format(len(domain_set)))
    print("Found {}".format(tot))

    with open("data_refined/domain_to_final_serial_list.json", "w") as ouf:
        json.dump(domain_to_final_serial_list, fp=ouf)



# print(get_anchestors("adas.asfdasdfsdafsd.p.com"))



