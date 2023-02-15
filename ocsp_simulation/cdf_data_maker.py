import json

import matplotlib.pyplot as plt
# 1460

def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


result_path = "results"
modes = ['cold', 'warm', 'normal']
staple_modes = ['stapledon', 'stapledoff']


def analyze_single_entry(e):
    try:
        # dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name, meta, _ = e
        dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name = e

        # if "demdex" in server_name or "mozilla" in server_name:
        #     return None, None

        old_ocsp_end = ocsp_2
        reactive_ocsp_end = max(ocsp_dns_2, established_time)
        # ask tijay -> gap between dns and tls
        proactive_ocsp_end = max(dns_start + (ocsp_dns_2 - ocsp_dns_1), established_time)
        tot_time = encrypted_data_time_app - client_hello_time

        if old_ocsp_end <= established_time:
            return 0, 0
        else:
            diff_reactive =  reactive_ocsp_end - old_ocsp_end
            diff_proactive = proactive_ocsp_end - old_ocsp_end
        return diff_reactive / tot_time, diff_proactive / tot_time
    except Exception as e:
        a = 1

def analyze_zeek_output(file):
    f = open(file)
    d = json.load(f)
    arr_reactive = []
    arr_proactive = []
    for e in d:
        try:
            reactive_ratio, proactive_ratio = analyze_single_entry(e)
            if reactive_ratio:
                arr_reactive.append(reactive_ratio)
            if proactive_ratio:
                arr_proactive.append(proactive_ratio)
        except Exception as err:
            a = 1
    return arr_reactive, arr_proactive


def analyze_init():
    store_dict = {}

    for mode in modes:
        for staple_mode in staple_modes:
            first_reactive_arr = []
            first_proactive_arr = []
            second_proactive_arr = []
            second_reactive_arr = []

            first_domains = 0
            second_domains = 0

            files = get_leaf_files("{}/{}/{}".format(result_path, mode, staple_mode))
            for file in files:
                segments = file.split("/")
                file_name = segments[-1]
                sub_segs = file_name.split("-")
                index_first = int(sub_segs[0])
                index_second = int(sub_segs[1][: -5])
                arr_reactive, arr_proactive = analyze_zeek_output(file)

                if index_first < 30000:
                    first_domains += index_second - index_first + 1
                    first_reactive_arr += arr_reactive
                    first_proactive_arr += arr_proactive
                else:
                    second_domains += index_second - index_first + 1
                    second_reactive_arr += arr_reactive
                    second_proactive_arr += arr_proactive

            mother_str = "{}-{}".format(mode, staple_mode)
            store = {}
            store["first_reactive_arr"] = first_reactive_arr
            store["second_reactive_arr"] = second_reactive_arr
            store["first_proactive_arr"] = first_proactive_arr
            store["second_proactive_arr"] = second_proactive_arr

            store["f_domains"] = first_domains
            store["l_domains"] = second_domains

            store_dict[mother_str] = store

    with open("mother_dict.json", "w") as ouf:
        json.dump(store_dict, fp=ouf)


def analyze_second_step():
    f = open("data/mother_dict.json")
    d = json.load(f)
    a = 1

analyze_init()















