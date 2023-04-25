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

ocsp_url_to_tuple_list = defaultdict(lambda : list())

files = get_files_from_dir('/net/data/luminati/no-nonce/post')
index = 0
files_numbered = []
for file in files:
    files_numbered.append((file, "{}/{}".format(index, len(files))))
    index += 1

def analyze_single_file(tuple):
    try:
        file, index = tuple
        import json
        f = open(file)
        g = json.load(f)
        for d in g:
            try:
                url = d['target']
                serial = d['serial_number']
                time_start = d['time-start']
                time_end = d['time-end']
                asn = d['hop']
                ocsp_response_status = d['ocsp_response_status']
                delegated_response = d['delegated_response']
                ocsp_cert_status = d['ocsp_cert_status']
                is_normal = d['is_normal']
                headers = d['headers']
                response_time_lum = find_response_time(headers['x-luminati-timeline'])
                if ocsp_response_status == "OCSPResponseStatus.SUCCESSFUL" and is_normal:
                    ocsp_url_to_tuple_list[url].append(
                        (asn, serial, delegated_response, time_end - time_start, response_time_lum))
            except:
                pass
        print("Done with {}".format(index))
    except:
        pass


    # "ocsp_response_status": "OCSPResponseStatus.SUCCESSFUL",
    # "delegated_response": true,
    # "ocsp_cert_status": "OCSPCertStatus.GOOD",
    # "is_normal": true

print("Total files {}".format(len(files_numbered)))

files_numbered = files_numbered[: 100]

pool = ThreadPool(100)
results = pool.map(analyze_single_file, files_numbered)
pool.close()
pool.join()

import json
with open("lum_summary.json", "w") as ouf:
    json.dump(ocsp_url_to_tuple_list, fp=ouf)