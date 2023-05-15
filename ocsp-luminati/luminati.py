import time
from multiprocessing.dummy import Pool as ThreadPool



def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files

def find_response_time(s):
    f_index = s.find("response")
    f_index = f_index + 9
    e_index = s[f_index:].find(",")
    a = int(s[f_index: f_index + e_index])

    b = 0

    try:
        f_index = s.find("dns_resolve")
        f_index = f_index + 12
        e_index = s[f_index:].find(",")
        b = int(s[f_index: f_index + e_index])
    except:
        pass
    return a, b

from collections import defaultdict

ocsp_url_to_err_list = defaultdict(lambda : list())

ocsp_url_to_tuple_list = defaultdict(lambda : list())

ocsp_url_counter = defaultdict(lambda : 0)

files = get_files_from_dir('/net/data/luminati/no-nonce/post')
index = 0
files_numbered = []
for file in files:
    files_numbered.append((file, "{}/{}".format(index, len(files))))
    index += 1

'''
    Meta:
    
    Post req <-> 
                 
                 
                    
    Number of OCSP URL
    Number of req sent
    Number of distinct serials:
    Number of ASNs

    # Number of req sent succ
    # Number of req sent unsucc

'''

ocsp_url_set = set()
num_req = 0
serial_set = set()
asn_set = set()
succ_req = 0
unsucc_req = 0

def analyze_single_file(tuple):
    global num_req, succ_req, unsucc_req, ocsp_url_set, serial_set, asn_set
    try:
        file, index = tuple
        import json
        f = open(file)
        g = json.load(f)
        for d in g:
            try:
                num_req += 1
                is_normal = d['is_normal']
                url = d['target']

                ocsp_url_set.add(url)

                asn = d['hop']
                serial = d['serial_number']
                pre_time = d['time-pre']

                serial_set.add(serial)
                asn_set.add(asn)

                ocsp_url_counter[url] += 1

                if not is_normal:
                    unsucc_req += 1
                    err_reason = d['error']
                    ocsp_url_to_err_list[url].append(
                        (asn, serial, err_reason, pre_time))
                    continue

                succ_req += 1

                time_start = d['time-start']
                time_end = d['time-end']

                ocsp_response_status = d['ocsp_response_status']
                delegated_response = d['delegated_response']
                ocsp_cert_status = d['ocsp_cert_status']
                is_normal = d['is_normal']
                headers = d['headers']
                response_time_lum = find_response_time(headers['x-luminati-timeline'])
                if ocsp_response_status == "OCSPResponseStatus.SUCCESSFUL" and is_normal:
                    ocsp_url_to_tuple_list[url].append(
                        (asn, serial, delegated_response, time_end - time_start, response_time_lum))

            except Exception as e:
                print(e)
        print("Done with {}".format(index))
    except Exception as e:
        print(e)


    # "ocsp_response_status": "OCSPResponseStatus.SUCCESSFUL",
    # "delegated_response": true,
    # "ocsp_cert_status": "OCSPCertStatus.GOOD",
    # "is_normal": true

print("Total files {}".format(len(files_numbered)))

files_numbered = files_numbered[: 100]

t1 = time.time()
pool = ThreadPool(100)
results = pool.map(analyze_single_file, files_numbered)
pool.close()
pool.join()
t2 = time.time()
print("Total time taken {} minutes".format((t2 - t1) / 60))

import json
with open("lum_data/lum_summary.json", "w") as ouf:
    json.dump(ocsp_url_to_tuple_list, fp=ouf)


summary = {
    "total_ocsp_url": len(ocsp_url_set),
    "total req sent": num_req,
    "succ": succ_req,
    "unsucc": unsucc_req,
    "total serials": len(serial_set),
    "total asn": len(asn_set)
}

with open("lum_data/lum_err_summary.json", "w") as ouf:
    json.dump(ocsp_url_to_err_list, fp=ouf)

with open("lum_data/meta_info_lum.json", "w") as ouf:
    json.dump(summary, fp=ouf, indent=2)

with open("lum_data/conuter.json", "w") as ouf:
    json.dump(ocsp_url_counter, fp=ouf)

