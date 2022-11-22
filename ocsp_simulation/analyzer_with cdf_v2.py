import json
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib

#base_path = '/Users/protick.bhowmick/zeek/'

global_normal_dns_rtt = []

def do_so(mode, sesh):
    base_path = '/net/data/dns-ttl/pcap/zeek_logs/{}/{}-{}/'.format(mode, sesh - 500 + 1, sesh)
    #base_path = '/home/protick/zeek_dumps/'
    def analyze_custom_logs():
        # serial_number = (start, end)
        logs = []

        for line in open('{}ocsp_ext_v1.log'.format(base_path), 'r'):
            cls = json.loads(line)
            logs.append((cls['ts'], 2, "ocsp_ext", cls))

        for line in open('{}http_ext_v1.log'.format(base_path), 'r'):
            cls = json.loads(line)
            event_type = cls['event_type']
            if event_type == 'request':
                logs.append((cls['ts'], 1, "http_request", cls))
            elif event_type == 'response':
                logs.append((cls['ts'], 3, "http_reply", cls))

        logs.sort(key=lambda x: (x[0], x[1], x[2]))

        serial_num_to_tuples = defaultdict(lambda: list())
        uid_to_serial = {}
        uid_to_req_time = {}

        for e in logs:

            flag = e[2]
            cls = e[3]

            if flag == 'http_request':
                t = cls['ts']
                uid = cls['uid']
                uid_to_req_time[uid] = t
            elif flag == 'ocsp_ext':
                uid = cls['uid']
                serial = cls['serialNumber']
                uid_to_serial[uid] = serial
            elif flag == 'http_reply':
                t = cls['ts']
                uid = cls['uid']
                if uid in uid_to_req_time and uid in uid_to_serial:
                    serial = uid_to_serial[uid]
                    serial_num_to_tuples[serial].append((uid_to_req_time[uid], t, uid))
                    del uid_to_serial[uid]
                    del uid_to_req_time[uid]
        return serial_num_to_tuples


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

    def get_cert_log():
        cert_log_custom = []
        fingerprint_to_serial = {}
        for line in open('{}x509.log'.format(base_path), 'r'):
            cert_log_custom.append(json.loads(line))
        for e in cert_log_custom:
            fingerprint_to_serial[e['fingerprint']] = e['certificate.serial']
        return fingerprint_to_serial

    def get_final_list():
        class Meta:
            pass

        server_name_to_lst = defaultdict(lambda: list())

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

        dns_log = []
        for line in open('{}dns.log'.format(base_path), 'r'):
            dns_log.append(json.loads(line))

        build_dns(dns_log)

        for e in ssl_log_custom:
            try:
                meta = Meta()
                for key in e:
                    meta.__setattr__(key, e[key])
                uid_to_info[meta.uid] = meta
            except Exception as e:
                pass

        for e in ssl_log:
            try:
                uid = e['uid']
                if uid in uid_to_info:
                    for key in e:
                        uid_to_info[uid].__setattr__(key, e[key])
            except Exception as e:
                pass

        for uid in uid_to_info:
            try:
                server_name = uid_to_info[uid].server_name
                client_hello_time = uid_to_info[uid].client_hello_time
                client_ip = uid_to_info[uid].__getattribute__('id.orig_h')
                ans_tuple = get_dns_time(server_name=server_name, client_hello_time=client_hello_time,
                                         client_ip=client_ip,
                                         dns_log=dns_log)
                if ans_tuple is not None:
                    uid_to_info[uid].__setattr__('dns_start', ans_tuple[0])
                    uid_to_info[uid].__setattr__('dns_end', ans_tuple[1])
            except:
                pass

        final_list = defaultdict(lambda: Meta())
        for uid in uid_to_info:
            if hasattr(uid_to_info[uid], 'dns_start'):
                final_list[uid] = uid_to_info[uid]

        return final_list

    init_time = time.time()

    uid_to_host = get_uid_to_host()
    fingerprint_to_serial = get_cert_log()
    serial_num_to_tuples = analyze_custom_logs()
    for key in serial_num_to_tuples:
        serial_num_to_tuples[key].sort()
    a = 1

    # all TLS timestamps with DNS
    final_list = get_final_list()
    index = 0

    def get_appropriate_tuple(serial, serial_num_to_tuples, server_hello, server_name):
        if serial not in serial_num_to_tuples:
            return None
        for t1, t2, uid in serial_num_to_tuples[serial]:
            if t1 > server_hello:
                host = None
                if uid in uid_to_host:
                    host = uid_to_host[uid]
                return t1, t2, host
        return None

    server_dns_name_to_lst = defaultdict(lambda: list())

    def build_dns(dns_log):
        for e in dns_log:
            try:
                server_dns_name_to_lst[e['query']].append(e)
                if 'rtt' in e and mode == 'normal_log':
                    global_normal_dns_rtt.append(e['rtt'])

            except:
                pass

    def get_dns_tuple(lim1, lim2, q_name):
        set_ans = None
        for e in server_dns_name_to_lst[q_name]:
            try:
                a = 1
                if e['query'] == q_name and lim1 <= e['ts'] < e['ts'] + e['rtt'] <= lim2:
                    if not set_ans:
                        set_ans = e['ts'], e['ts'] + e['rtt']
                    elif set_ans[0] < e['ts']:
                        set_ans = e['ts'], e['ts'] + e['rtt']
                a = 1
            except Exception as err:
                a = 1
        if set_ans is None:
            return None, None
        return set_ans

    dns_log = []
    for line in open('{}dns.log'.format(base_path), 'r'):
        dns_log.append(json.loads(line))
    build_dns(dns_log)
    # 643856ed9d2fce5408ca7ba627126996f20ceb0827f6ebd4fe7d80cea7a6a2c5

    for p in final_list:
        try:
            e = final_list[p]
            if hasattr(e, "cert_chain_fps"):
                fp = e.cert_chain_fps[0]
                serial = fingerprint_to_serial[fp]
                server_hello = e.server_hello_time
                time_tuple = get_appropriate_tuple(serial, serial_num_to_tuples, server_hello, e.server_name)
                if time_tuple is not None:
                    final_list[p].ocsp_1 = time_tuple[0]
                    final_list[p].ocsp_2 = time_tuple[1]
                    final_list[p].ocsp_host = time_tuple[2]

                    # need change if dns not present !!

                    final_list[p].ocsp_dns_1, final_list[p].ocsp_dns_2 = get_dns_tuple(e.server_hello_time,
                                                                                       time_tuple[0],
                                                                                       time_tuple[2])
                else:
                    a = 1
        except:
            pass

    version_set = set()

    # 1460
    master_arr = []
    for p in final_list:
        try:
            e = final_list[p].__dict__
            if 'ocsp_1' not in e and 'ocsp_2' not in e:
                continue
            if e['resumed']:
                continue
            index += 1
            arr = []
            arr.append(e["dns_start"])
            arr.append(e["dns_end"])
            arr.append(e["client_hello_time"])
            arr.append(e["server_hello_time"])
            arr.append(e['change_cipher_time_client'])
            arr.append(e['change_cipher_time_server'])
            arr.append(e['established_time'])
            arr.append(e['encrypted_data_time_app'])

            if e['version'] == 'TLSv13':
                continue
            if e['ocsp_1'] > e['encrypted_data_time_app']:
                continue
            if e['ocsp_dns_1'] is not None:
                a = 1
            # draw_line(arr, "x", "y", e['server_name'], index, e['ocsp_1'],  e['ocsp_2'], e['ocsp_dns_1'], e['ocsp_dns_2'])

            tp = arr.copy()
            tp = tp + [e['ocsp_dns_1'], e['ocsp_dns_2'], e['ocsp_1'], e['ocsp_2'], e['server_name']]
            master_arr.append(tp)
            a = 1
        except:
            pass

    print("Time taken {}".format((time.time() - init_time) / 60))

    with open("exp/firefox_{}_{}-{}.json".format(mode, sesh - 500 + 1, sesh), "w") as ouf:
        json.dump(master_arr, fp=ouf)


modes = ['cold_log', 'warm_log', 'normal_log']
for mode in modes:
    init = 1
    sesh = 500
    while sesh <= 5000:
        do_so(mode, sesh)
        init += 500
        sesh += 500
        print("Done with {} {}".format(mode, sesh))

with open("exp/normal_rtt.json", "w") as ouf:
    json.dump(global_normal_dns_rtt, fp=ouf)
