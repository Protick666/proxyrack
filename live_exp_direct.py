import asyncio
import os
import time
import uuid

import requests
from dns import message, asyncquery, rdatatype


from local import LOCAL

QUERY_URL = 'ttlexp.exp.net-measurement.net'

# TODO local file, instance, bind transfer
ALLOWED_CHUNK = 80
ALLOWED_TTL = 60

phase_1_dump = list()
phase_1_info = dict()

resolver_to_server_version = {}

bucket = 1


def shift(seq, n=0):
    a = n % len(seq)
    return seq[a:] + seq[:a]


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
    return True


async def ip_test(tp):
    global phase_1_dump
    global phase_1_info

    try:
        if len(tp) == 4:
            url, asn, cn, isp = tuple(tp)
            phase = 1
            req_uid = str(uuid.uuid4())
        else:
            url, asn, cn, isp, req_uid, phase = tuple(tp)

        domain = "{}.{}.ttlexp.exp.net-measurement.net".format(req_uid, bucket)

        q = message.make_query(domain, rdatatype.A)
        a = await asyncquery.udp(q, url, timeout=2)
        ip = str(list(a.answer[0].items.keys())[0])
        ttl = a.answer[0].ttl

        req_sent_time = time.time()

        # try:
        #     z = message.make_query("version.bind", rdatatype.TXT, rdclass=3)
        #     aa = await asyncquery.udp(z, url, timeout=2)
        #     ans = str(list(aa.answer[0].items.keys())[0])
        #     resolver_to_server_version[url] = ans
        # except:
        #     pass

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
            return 1
    except Exception as e:
        a = 1
        return -1


async def send_reqs(chosen_hop_list):
    # TODO (ip, asn, cn, isp)
    tasks = []
    for tp in chosen_hop_list:
        tasks.append(ip_test(tp))
    await asyncio.gather(*tasks)


def process_chunks(hops, chunk_size, ttl, phase=1):
    global phase_1_info
    req_id_arr = []
    hops = hops.copy()

    if phase == 1:
        asn_chunks = chunks(hops, chunk_size)
    else:
        temp_tuple_arr = []
        for req_id in hops:
            temp_tuple_arr.append(tuple(phase_1_info[req_id]["tuple"]) + (req_id, phase))
        asn_chunks = chunks(temp_tuple_arr, chunk_size)

    starting_time = time.time()
    done_chunks = 0
    for chunk in asn_chunks:
        asyncio.run(send_reqs(chosen_hop_list=chunk))
        done_chunks += 1
        time_now = time.time()
        #print(time_now - starting_time)
        if time_now - starting_time > ttl or ttl - (time_now - starting_time) <= 5:
            break

    return done_chunks


def carry_out_exp(hops, ttl, cool_down, chunk_size):

    change_bind_config(file_version='first', bucket_id=bucket)
    done_chunks = process_chunks(hops, chunk_size, ttl, phase=1)

    change_bind_config(file_version='second', bucket_id=bucket)
    from time import sleep
    print("wait start")
    sleep(cool_down + 5)
    print("wait end")

    global phase_1_dump
    process_chunks(phase_1_dump, chunk_size, ttl,  phase=2)
    return done_chunks


def luminati_asn_ttl_crawler_req(exp_id, TTL_IN_SEC, chunk_size, index, chosen_hop_list):
    COOL_DOWN_PERIOD = TTL_IN_SEC
    global phase_1_dump
    global phase_1_info

    phase_1_dump = list()
    phase_1_info = dict()

    done_chunks = carry_out_exp(hops=chosen_hop_list,
                                ttl=TTL_IN_SEC,
                                cool_down=COOL_DOWN_PERIOD,
                                chunk_size=chunk_size)

    from pathlib import Path
    dict_to_store = dict(phase_1_info)
    dump_directory = "cross_check_direct_v20/"
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    dump_index = str(uuid.uuid4())

    import json
    with open("{}/{}.json".format(dump_directory, dump_index), "w") as ouf:
        json.dump(dict_to_store, fp=ouf)

    return done_chunks


def zeus(ttl):
    f = open("target_list.json")
    import json
    solo_hop_list = json.load(f)
    import random
    random.shuffle(solo_hop_list)
    # TODO calc shift
    chosen_hop_list = []
    for i in range(8):
        chosen_hop_list = chosen_hop_list + solo_hop_list

    target = len(chosen_hop_list)
    # target = 50
    done = 0

    for i in range(500):
        print("starting new iteration")
        done_chunks = luminati_asn_ttl_crawler_req(exp_id="proxy_check",
                                                 TTL_IN_SEC=ttl,
                                                 chunk_size=ALLOWED_CHUNK, index=i,
                                                 chosen_hop_list=chosen_hop_list)
        print("Done {}".format(done_chunks))
        chosen_hop_list = shift(chosen_hop_list, done_chunks * ALLOWED_CHUNK)
        done += done_chunks * ALLOWED_CHUNK
        print("Done {}/{}".format(done, target))
        if done >= target:
            break
        time.sleep(5)

    # import json
    # dump_directory = "cross_check_direct_v7/"
    # with open("{}/{}.json".format(dump_directory, "chaos"), "w") as ouf:
    #     json.dump(resolver_to_server_version, fp=ouf)


zeus(ALLOWED_TTL)
