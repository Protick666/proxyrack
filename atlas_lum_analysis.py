import json
from collections import defaultdict
from ripe.atlas.sagan import DnsResult

'''
Step 1: for small,big:
            analyze probe result:
            asn -> uncached list
            asn -> cached list
'''

def get_probe_id_to_ans_dict():
    f = open("/Users/protick.bhowmick/Downloads/20220708.json")
    d = json.load(f)
    probe_to_asn = {}
    for e in d['objects']:
        if not e['is_public']:
            continue
        probe_to_asn[e['id']] = e['asn_v4']
    return probe_to_asn

def get_measurement_list(idenfifier):
    file_name = "{}_dns.json".format(idenfifier)
    # if idenfifier == "small":
    #     f = open("small_dns.json")
    # elif idenfifier == "big":
    #     f = open("big_dns.json")
    # else:
    #     return []
    f = open(file_name)

    measurement_lst = json.load(f)
    return measurement_lst

    # for e in measurement_lst:
    #     my_dns_result = DnsResult(e)
    #     for r in my_dns_result.responses:
    #         try:
    #             ttl = r.abuf.answers[0].ttl
    #             time = r.response_time
    #             print(ttl, time)
    #         except:
    #             pass

def get_ripe_asns():
    lst = []
    for indentifier in ['small', 'big', 'big_2', 'small_2']:
        lst = lst + get_measurement_list(idenfifier=indentifier)

    probe_id_to_asn_dict = get_probe_id_to_ans_dict()
    asn_set = set()
    for e in lst:
        asn_set.add(probe_id_to_asn_dict[e['prb_id']])
    with open("atlas_asns.json", "w") as ouf:
        json.dump(list(asn_set), fp=ouf)


def analyze_ripe_data():
    small_measurement_list = get_measurement_list(idenfifier="small") + get_measurement_list(idenfifier="small_2")
    big_measurement_list = get_measurement_list(idenfifier="big") + get_measurement_list(idenfifier="big_2")

    probe_id_to_ans_dict = get_probe_id_to_ans_dict()

    asn_to_uncached_rt = {
        "small": defaultdict(lambda: list()),
        "big": defaultdict(lambda: list())
    }
    asn_to_cached_rt = {
        "small": defaultdict(lambda: list()),
        "big": defaultdict(lambda: list())
    }

    cached_rt_list, uncached_rt_list = defaultdict(lambda: list()), defaultdict(lambda: list())

    done_asns = []

    big_inc_set = ['81.56.26.23', '71.87.72.51', '193.22.6.132', '94.21.214.19', '109.117.221.75', '65.32.192.167', '188.235.196.94', '111.223.65.93', '78.31.79.167', '184.83.244.185', '207.188.170.199']

    for data_type in ["big"]:
        source_str = "{}_measurement_list".format(data_type)
        data_source = eval(source_str)
        if data_type == 'big':
            a = 1
        cor = 0
        cor_set = set()
        inc_set = set()
        inc_set_buffer = set()

        for e in data_source:
            if e['from'] in big_inc_set:
                a = 1

            my_dns_result = DnsResult(e)
            for r in my_dns_result.responses:
                try:
                    probe_id = my_dns_result.probe_id
                    asn = probe_id_to_ans_dict[probe_id]
                    done_asns.append(asn)
                    ttl = r.abuf.answers[0].ttl
                    rt = r.response_time

                    cor_set.add(e['from'])

                    if ttl == 3600:
                        asn_to_uncached_rt[data_type][asn].append(rt)
                        uncached_rt_list[data_type].append(rt)
                    else:
                        asn_to_cached_rt[data_type][asn].append(rt)
                        cached_rt_list[data_type].append(rt)
                except Exception as exp:
                    inc_set.add(e['from'])
                    if r.abuf is not None and e['from'] in big_inc_set:
                        a = 1
                        try:
                            print(r.abuf.edns0.udp_size)
                            inc_set_buffer.add(e['from'])
                        except:
                            a = 1
        a = 1


    master_dict = {
        "asn_to_uncached_rt": asn_to_uncached_rt,
        "asn_to_cached_rt": asn_to_cached_rt,
        "cached_rt_list": cached_rt_list,
        "uncached_rt_list": uncached_rt_list
    }

    # with open("done_asns.json", "w") as ouf:
    #     json.dump(done_asns, fp=ouf)

    with open("ripe_atlas_analysis_dns.json", "w") as ouf:
        json.dump(master_dict, fp=ouf)


# get_ripe_asns()
analyze_ripe_data()