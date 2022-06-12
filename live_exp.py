import binascii
import logging
import time
import uuid
from multiprocessing import Pool, Manager
from functools import partial
import dnslib
import requests
import socks


QUERY_URL = 'ttlexp.exp.net-measurement.net'

username = 'tijay'
password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'
PROXY_RACK_DNS = "premium.residential.proxyrack.net:9000"

ALLOWED_CHUNK = 60
ALLOWED_TTL = 60
ALLOWED_PROCESS = 40

def shift(seq, n=0):
    a = n % len(seq)
    return seq[-a:] + seq[:-a]


def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


def change_bind_config(file_version, bucket_id, depth=0):
    if depth == 5:
        return False

    URL = "http://52.44.221.99:8000/update-bind"
    PARAMS = {'file_version': file_version, 'bucket_id': str(bucket_id)}
    r = requests.get(url=URL, params=PARAMS)
    data = r.json()
    if r.status_code != 200:
        print("!!!!!!!!!! Bind server API not working")
        return change_bind_config(file_version, bucket_id, depth + 1)
    print("Bind server API working")
    return True



def ip_test(phase_1_dump, phase_1_info, tp, is_second=False):
    try:
        if len(tp) == 4:
            url, asn, cn, isp = tuple(tp)
            phase = 1
            req_uid = str(uuid.uuid4())
        else:
            url, asn, cn, isp, req_uid, phase = tuple(tp)

        domain = "{}.1.ttlexp.exp.net-measurement.net".format(req_uid)
        d = dnslib.DNSRecord.question(domain)
        query_data = d.pack()
        dnsPacket = query_data

        s = socks.socksocket()
        s.settimeout(30)
        s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', 9000, True,
                    username + "-timeoutSeconds-30-country-{}-isp-{}".format(cn, isp), password)

        req_sent_time = time.time()

        try:
            s.connect((url, 53))
            s.send(dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket)
        except Exception as e:
            result = str(e)
            s.close()
            print("!!!!!!!!!! Fail")
            return
        try:
            r = s.recv(1024)
            r = r.hex()
            response = binascii.unhexlify(r[4:])
            s.close()
        except:
            result = 'noResponse'
            s.close()
            print("!!!!!!!!!! Fail")
            return

        print("!!!!!!!!!! Success")
        parsed_result = dnslib.DNSRecord.parse(response)
        a = 1
        ip = str(parsed_result.rr[0].rdata)
        ttl = parsed_result.rr[0].ttl
        if phase == 1:
            phase_1_dump.append(req_uid)
            nested_dict = {}
            nested_dict["ip_1"] = ip
            nested_dict["ttl_1"] = ttl
            nested_dict["tuple"] = tp
            nested_dict["timestamp_1"] = req_sent_time
            phase_1_info[req_uid] = nested_dict
        else:
            nested_dict = phase_1_info[req_uid]

            nested_dict["timestamp_2"] = req_sent_time
            nested_dict["ip_2"] = ip
            nested_dict["ttl_2"] = ttl

            phase_1_info[req_uid] = nested_dict

        a = 1
    except:
        return


def send_reqs(chosen_hop_list, phase_1_dump, phase_1_info, phase):
    # TODO (ip, asn, cn, isp)

    p = Pool(ALLOWED_PROCESS)
    func = partial(ip_test, phase_1_dump, phase_1_info)
    result = p.map(func, chosen_hop_list)
    p.close()


def process_chunks(hops, chunk_size, ttl, phase_1_dump, phase_1_info, phase=1):
    req_id_arr = []

    if phase == 1:
        asn_chunks = chunks(hops, chunk_size)
    else:
        temp_tuple_arr = []
        for req_id in hops:
            temp_tuple_arr.append(tuple(phase_1_info[req_id]["tuple"]) + (req_id, phase))
        asn_chunks = chunks(temp_tuple_arr, chunk_size)

    starting_time = time.time()
    for chunk in asn_chunks:
        send_reqs(chosen_hop_list=chunk, phase_1_dump=phase_1_dump, phase_1_info=phase_1_info, phase=phase)
        time_now = time.time()
        if time_now - starting_time > ttl or ttl - (time_now - starting_time) <= 5:
            break


def carry_out_exp(hops, ttl, cool_down, chunk_size, phase_1_dump, phase_1_info):

    change_bind_config(file_version='first', bucket_id=1)
    process_chunks(hops, chunk_size, ttl, phase_1_dump, phase_1_info, phase=1)

    change_bind_config(file_version='second', bucket_id=1)
    from time import sleep
    sleep(cool_down + 5)

    process_chunks(phase_1_dump, chunk_size, ttl, phase_1_dump, phase_1_info,  phase=2)


def luminati_asn_ttl_crawler_req(exp_id, TTL_IN_SEC, chunk_size, index):
    COOL_DOWN_PERIOD = TTL_IN_SEC

    manager = Manager()
    phase_1_dump = manager.list()
    phase_1_info = manager.dict()


    # TODO (ip, asn, cn, isp)
    f = open("target_list.json")
    import json

    solo_hop_list = json.load(f)
    solo_hop_list = shift(solo_hop_list, index * 30)

    chosen_hop_list = []
    for i in range(5):
        chosen_hop_list = chosen_hop_list + solo_hop_list


    carry_out_exp(hops=chosen_hop_list,
                  ttl=TTL_IN_SEC,
                  cool_down=COOL_DOWN_PERIOD,
                  chunk_size=chunk_size,
                  phase_1_dump=phase_1_dump,
                  phase_1_info=phase_1_info)

    # TODO store
    from pathlib import Path
    dict_to_store = dict(phase_1_info)
    dump_directory = "cross_check/"
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    import json
    with open("{}/{}.json".format(dump_directory, index), "w") as ouf:
        json.dump(dict_to_store, fp=ouf)


def zeus(ttl):
    for i in range(100):
        luminati_asn_ttl_crawler_req(exp_id="proxy_check",
                                     TTL_IN_SEC=ttl,
                                     chunk_size=ALLOWED_CHUNK, index = i)
        time.sleep(30)


if __name__ == '__main__':
    zeus(ALLOWED_TTL)
