import json
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib

base_path = '/home/protick/zeek_final/anon/anon.'

# TODO fix
def is_vt(ip):
    return True

def analyze_custom_logs(allowed_uids):
    # serial_number = (start, end)
    logs = []

    for line in open('{}http_ext_v1.log'.format(base_path), 'r'):
        cls = json.loads(line)
        event_type = cls['event_type']
        if event_type == 'request':
            logs.append((cls['ts'], 1, "http_request", cls))
        elif event_type == 'response':
            logs.append((cls['ts'], 3, "http_reply", cls))

    logs.sort(key=lambda x: (x[0], x[1], x[2]))

    uid_to_response_time = {}
    uid_to_req_time = {}

    for e in logs:
        flag = e[2]
        cls = e[3]

        if flag == 'http_request':
            t = cls['ts']
            uid = cls['uid']
            uid_to_req_time[uid] = t
        elif flag == 'http_reply':
            t = cls['ts']
            uid = cls['uid']
            if uid in uid_to_req_time:
                response_time =  t - uid_to_req_time[uid]
                del uid_to_req_time[uid]
                if uid in allowed_uids:
                    uid_to_response_time[uid] = response_time
    return uid_to_response_time


def get_uid_to_host():
    log_custom = []
    uid_to_host = {}
    for line in open('{}http.log'.format(base_path), 'r'):
        log_custom.append(json.loads(line))
    for e in log_custom:
        try:
            uid_to_host[e['uid']] = e['host']
        except:
            pass
    return uid_to_host


def get_host_to_uid_list(ocsp_host_set):
    log_custom = []
    uids_of_interest_in_http = set()
    host_to_uid = defaultdict(lambda : list())
    for line in open('{}http.log'.format(base_path), 'r'):
        log_custom.append(json.loads(line))
    for e in log_custom:
        try:
            if e['host'] not in ocsp_host_set:
                continue
            host_to_uid[e['host']].append(e['uid'])
            uids_of_interest_in_http.add(e['uid'])
        except:
            pass
    return host_to_uid, uids_of_interest_in_http


def get_cert_log():
    cert_log_custom = []
    fingerprint_to_serial = {}
    for line in open('{}x509.log'.format(base_path), 'r'):
        cert_log_custom.append(json.loads(line))
    for e in cert_log_custom:
        fingerprint_to_serial[e['fingerprint']] = e['certificate_serial']
    return fingerprint_to_serial


def get_final_list():
    class Meta:
        pass

    server_name_to_lst = defaultdict(lambda : list())
    def build_dns(dns_log):
        for e in dns_log:
            try:
                server_name_to_lst[e['query']].append(e)
            except:
                pass

    def get_dns_time(server_name, client_hello_time, client_ip, dns_log):
        set_ans = None
        for e in server_name_to_lst[server_name]:
            try:
                if e['id.orig_h'] == client_ip and e['query'] == server_name and e['ts'] < client_hello_time:
                    if not set_ans:
                        set_ans = e['ts'], e['ts'] + e['rtt']
                    elif set_ans[0] < e['ts']:
                        set_ans = e['ts'], e['ts'] + e['rtt']
            except:
                pass
        return set_ans

    uid_to_info = defaultdict(lambda: Meta())

    ssl_log_custom = []
    for line in open('{}ssl_ext_v1.log'.format(base_path), 'r'):
        ssl_log_custom.append(json.loads(line))

    ssl_log = []
    for line in open('{}ssl.log'.format(base_path), 'r'):
        ssl_log.append(json.loads(line))

    print(len(ssl_log_custom), len(ssl_log))

    # These lines are dns stuff
    # dns_log = []
    # for line in open('{}dns.log'.format(base_path), 'r'):
    #     dns_log.append(json.loads(line))
    #
    # build_dns(dns_log)

    for e in ssl_log_custom:
        try:
            meta = Meta()
            for key in e:
                meta.__setattr__(key, e[key])
            uid_to_info[meta.uid] = meta
        except Exception as e:
            print(e)
            pass

    for e in ssl_log:
        try:
            uid = e['uid']
            if uid in uid_to_info:
                for key in e:
                    # for format mismatch
                    if key == 'ts':
                        continue
                    uid_to_info[uid].__setattr__(key, e[key])
        except Exception as e:
            print(e)
            pass

    return uid_to_info


def get_base_domain(ocsp_url):
    ocsp_host = ocsp_url
    if ocsp_host.startswith("http://"):
        ocsp_host = ocsp_host[7:]
    if "/" in ocsp_host:
        ocsp_host = ocsp_host[0: ocsp_host.find("/")]
    return ocsp_host

def build_dns():
    dns_log = []
    for line in open('{}dns.log'.format(base_path), 'r'):
        dns_log.append(json.loads(line))

    qname_to_rtt_list_vt = defaultdict(lambda : list())
    qname_to_rtt_list_nvt = defaultdict(lambda : list())

    for e in dns_log:
        try:
            source = e['id_orig_h']
            if is_vt(source):
                rtt = e['rtt']
                qname = e['query']
                qname_to_rtt_list_vt[qname].append(rtt)
            else:
                rtt = e['rtt']
                qname = e['query']
                qname_to_rtt_list_nvt[qname].append(rtt)
        except:
            pass

    return qname_to_rtt_list_vt, qname_to_rtt_list_nvt

def get_fingerprint_to_ocsp_host():
    # fingerprints['1997274781c233029a159c5b4ff38c7e5e0f68183223d6b758947766e6530ee0']['parsed']['extensions']['authority_info_access']['ocsp_urls'][0]
    d = {}

    f = open("/home/protick/proxyrack/ocsp_simulation/fingerprint_to_meta.json")
    fingerprints = json.load(f)
    for fingerprint in fingerprints:
        try:
            host = fingerprints[fingerprint]['parsed']['extensions']['authority_info_access']['ocsp_urls'][0]
            host = get_base_domain(host)
            d[fingerprint] = host
        except:
            pass

    f = open("/home/protick/proxyrack/ocsp_simulation/fingerprint_to_meta_2.json")
    fingerprints = json.load(f)
    for fingerprint in fingerprints:
        try:
            d[fingerprint] = fingerprints[fingerprint]['parsed']['extensions']['authority_info_access']['ocsp_urls'][0]
        except:
            pass
    return d

def get_median_dict(d):
    import statistics
    key_to_median = {}

    for k in d:
        lst = []
        try:
            for element in d[k]:
                lst.append(element)
        except:
            pass
        if len(lst) == 0:
            continue
        median_element = statistics.median(lst)
        key_to_median[k] = median_element

    return key_to_median


def until_first_filter():
    final_list = get_final_list()
    #server_dns_name_to_lst = defaultdict(lambda: list())

    # dns stuff
    # dns_log = []
    # for line in open('{}dns.log'.format(base_path), 'r'):
    #     dns_log.append(json.loads(line))
    # build_dns(dns_log)

    # ocsp stuff

    ocsp_host_set = set()

    list_only_tls2 = []
    server_name_set = set()
    for p in final_list:
        e = final_list[p]
        try:
            if hasattr(e, "cert_chain_fps"):
                fp = e.cert_chain_fps[0]
                final_list[p].fingerprint = fp
                j = final_list[p].__dict__
                if j['version'] == 'TLSv12' and not j['resumed']:
                    server_name_set.add(j['server_name'])
                    list_only_tls2.append(j)
        except:
            pass
    print("TLS connections {} for {} servers".format(len(list_only_tls2), len(server_name_set)))

    with open('only_2.json', "w") as ouf:
        json.dump(list_only_tls2, fp=ouf)

    # cert was recorded in x509, necessary fields are there, corresponding entry in censys
    server_name_set = set()
    list_only_first_filter = []
    fingerprint_to_ocsp_host = get_fingerprint_to_ocsp_host()

    for e in list_only_tls2:
        fields = ['client_hello_time', 'server_hello_time', 'change_cipher_time_server', 'server_name', 'fingerprint']
        for field in fields:
            if field not in e:
                continue
        if e['fingerprint'] not in fingerprint_to_ocsp_host:
            continue
        e['ocsp_host'] = fingerprint_to_ocsp_host[e['fingerprint']]
        ocsp_host_set.add(fingerprint_to_ocsp_host[e['fingerprint']])
        server_name_set.add(e['server_name'])
        list_only_first_filter.append(e)

    print("TLS connections after first filter {}, for {} servers".format(len(list_only_first_filter), len(server_name_set)))

    with open('first_filter.json', "w") as ouf:
        json.dump(list_only_first_filter, fp=ouf)



    host_to_uid_list, uids_of_interest_in_http = get_host_to_uid_list(ocsp_host_set)
    uid_to_response_time = analyze_custom_logs(allowed_uids=uids_of_interest_in_http)

    qname_to_rtt_list_vt, qname_to_rtt_list_nvt = build_dns()

    qname_to_median_rtt_vt = get_median_dict(qname_to_rtt_list_vt)
    qname_to_median_rtt_nvt = get_median_dict(qname_to_rtt_list_nvt)

    import statistics
    host_to_median_http_time = {}


    for host in host_to_uid_list:
        lst = []
        try:
            for uid in host_to_uid_list[host]:
                lst.append(uid_to_response_time[uid])
        except:
            pass
        if len(lst) == 0:
            continue
        median_response_time = statistics.median(lst)
        host_to_median_http_time[host] = median_response_time

    # qname_to_median_rtt_vt = get_median_dict(qname_to_rtt_list_vt)
    # qname_to_median_rtt_nvt = get_median_dict(qname_to_rtt_list_nvt)
    # host_to_median_http_time[host] = median_response_time

    perc_change = []
    perc_change_cache = []

    for e in list_only_first_filter:
        #         fields = ['client_hello_time', 'server_hello_time', 'change_cipher_time_server', 'server_name', 'fingerprint']
        server_name = e['server_name']
        ocsp_host = e['ocsp_host']

        dns_A_time = None
        if server_name in qname_to_median_rtt_vt:
            dns_A_time = qname_to_median_rtt_vt[server_name]
        elif server_name in qname_to_median_rtt_nvt:
            dns_A_time = qname_to_median_rtt_nvt[server_name]

        dns_OCSP_time = None
        if ocsp_host in qname_to_median_rtt_vt:
            dns_OCSP_time = qname_to_median_rtt_vt[ocsp_host]
        elif ocsp_host in qname_to_median_rtt_nvt:
            dns_OCSP_time = qname_to_median_rtt_nvt[ocsp_host]

        ocsp_http_time = None
        if ocsp_host in host_to_median_http_time:
            ocsp_http_time = host_to_median_http_time[ocsp_host]

        if dns_A_time and dns_OCSP_time and ocsp_http_time:
            client_hello_time = e['client_hello_time']
            server_hello_time = e['server_hello_time'] - client_hello_time + dns_A_time
            change_cipher_time_server = e['change_cipher_time_server'] - client_hello_time + dns_A_time
            encrypted_data_time_app = None
            if 'encrypted_data_time_app' in e:
                encrypted_data_time_app = e['encrypted_data_time_app'] - client_hello_time + dns_A_time


            # think why **
            old_finish_time = change_cipher_time_server

            ocsp_http_finish_time = max(server_hello_time + ocsp_http_time, old_finish_time)

            ocsp_dns_fetch = dns_OCSP_time

            if ocsp_dns_fetch < old_finish_time:
                ocsp_dns_finish_time = old_finish_time
            else:
                ocsp_dns_finish_time = ocsp_dns_fetch


            tot_time = ocsp_http_finish_time - client_hello_time

            perc_change.append((ocsp_dns_finish_time - ocsp_http_finish_time) / tot_time)

    with open('perc_change.json', "w") as ouf:
        json.dump(perc_change, fp=ouf)

    for e in list_only_first_filter:
        #         fields = ['client_hello_time', 'server_hello_time', 'change_cipher_time_server', 'server_name', 'fingerprint']
        server_name = e['server_name']
        ocsp_host = e['ocsp_host']

        dns_A_time = .5/1000
        dns_OCSP_time = .5/1000

        ocsp_http_time = None
        if ocsp_host in host_to_median_http_time:
            ocsp_http_time = host_to_median_http_time[ocsp_host]

        if dns_A_time and dns_OCSP_time and ocsp_http_time:
            client_hello_time = e['client_hello_time']
            server_hello_time = e['server_hello_time'] - client_hello_time + dns_A_time
            change_cipher_time_server = e['change_cipher_time_server'] - client_hello_time + dns_A_time
            encrypted_data_time_app = None
            if 'encrypted_data_time_app' in e:
                encrypted_data_time_app = e['encrypted_data_time_app'] - client_hello_time + dns_A_time
            # think why **
            old_finish_time = change_cipher_time_server

            ocsp_http_finish_time = max(server_hello_time + ocsp_http_time, old_finish_time)

            ocsp_dns_fetch = dns_OCSP_time

            if ocsp_dns_fetch < old_finish_time:
                ocsp_dns_finish_time = old_finish_time
            else:
                ocsp_dns_finish_time = ocsp_dns_fetch


            tot_time = ocsp_http_finish_time - client_hello_time

            perc_change_cache.append((ocsp_dns_finish_time - ocsp_http_finish_time) / tot_time)

    with open('perc_change_cache.json', "w") as ouf:
        json.dump(perc_change_cache, fp=ouf)


