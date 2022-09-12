'''

    * Find out -> Total distinct certs in this period

    * Distinct domains it was mapped for -> *

    * All distinct domains -> [serial numbers]

'''

import json


def read_data_as_s(file_name):
    d = open("/net/data/dns-ttl/certstream/{}".format(file_name)).read().splitlines()
    return d

def get_data(file_name, filter_by_message_type):
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

f_names = ["dump2.json", "dump1.json", "dump.json"]
for f_name in f_names:
    certs = get_data(file_name=f_name, filter_by_message_type=False)
    with open("data_refined/{}".format(f_name), "w") as ouf:
        json.dump(certs, fp=ouf)
