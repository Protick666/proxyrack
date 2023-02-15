import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.pyplot as plt

def multiple_line_drawer(N, x_list, y_list, label_list, title='x', marker='.'):
    # import seaborn as sns
    # sns.set()
    #fig, axs = plt.subplots(figsize=(10, 20))
    # No of data points used
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

    fig, ax = plt.subplots(figsize=(10, 8))

    for i in range(N):
        y_lst_in_ms = [e * 1000 for e in y_list[i]]
        plt.plot(x_list[i], y_lst_in_ms, label=label_list[i], marker=marker)
    # plt.xlabel('Iterations')
    plt.ylabel('Response time in milliseconds')
    plt.legend(loc='best')

    # x_ticks = [e[0] for e in tick_index]
    # x_ticks_labels = [e[1] for e in tick_index]
    # plt.xticks(x_ticks, x_ticks_labels)

    plt.title(title)

    import random
    # plt.savefig('ttl_result/{}.png'.format(random.randint(1, 1000)), bbox_inches="tight")
    plt.show()
    plt.clf()

def get_smaller_cdf(x, y):
    smaller_points = []
    pre = 0
    for i in range(1, len(x)):
        if x[i] == x[i - 1]:
            continue
        smaller_points.append((x[i - 1], pre))
        smaller_points.append((x[i - 1], y[i - 1]))
        # ref.append((x[i - 1], y[i - 1], y[i - 1] - pre, (y[i - 1] - pre) * len(x)))
        pre = y[i - 1]
    smaller_points.append((x[-1], pre))
    smaller_points.append((x[-1], y[-1]))

    x_x = [e[0] for e in smaller_points]
    y_y = [e[1] for e in smaller_points]
    return x_x, y_y

# 1460
def cdf_multiple(x_list, label_lst, title, x_label):
    import seaborn as sns
    sns.set()

    fig, ax = plt.subplots(figsize=(14, 8))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.xlabel(x_label)
    plt.ylabel("CDF")
    plt.title(title)

    index = 0
    allowed_ttl = [1, 5, 15, 30, 60]

    index = 0
    for lst in x_list:
        lb = label_lst[index]
        l_trunc = [x for x in lst]
        label = label_lst[index]

        arr = l_trunc
        N = len(arr)
        data = np.array(arr)
        x = np.sort(data)
        y = np.arange(N) / float(N)

        import csv

        x_x, y_y = get_smaller_cdf(x, y)
        new_list = zip(x_x, y_y)
        # with open("paper_cdf/cdn-{}.csv".format(lb), 'w') as csvfile:
        #     filewriter = csv.writer(csvfile)
        #     filewriter.writerows(new_list)

        plt.plot(x, y, marker='.', label=label, lw=.1)
        index += 1
        # plt.show()
    # plt.axvline(x=1232)
    # plt.text(x_pos_ratio + .1, .5, "at y = {} % : {} {}s".format(x_line_threshold * 100, x[i], xlabel), fontsize=22)

    plt.legend(
        loc='best', shadow=True,
    )

    plt.show()
    plt.clf()
    # plt.savefig('graphs_final_3/comodo.png', bbox_inches="tight", format='png')
    # plt.clf()


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

        base_dns = dns_end - dns_start
        ocsp_dns = ocsp_dns_2 - ocsp_dns_1
        ocsp_http = ocsp_2 -ocsp_1
        base_tls = established_time - client_hello_time
        tot_ocsp_overhead = ocsp_2 - ocsp_dns_1

        graph_tuple = (dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead)

        if "demdex" in server_name or "mozilla" in server_name:
            return None, None, graph_tuple

        old_ocsp_end = ocsp_2
        reactive_ocsp_end = max(ocsp_dns_2, established_time)
        # ask tijay -> gap between dns and tls
        proactive_ocsp_end = max(dns_start + (ocsp_dns_2 - ocsp_dns_1), established_time)
        tot_time = encrypted_data_time_app - client_hello_time

        if old_ocsp_end <= established_time:
            return 0, 0, graph_tuple, 0, 0
        else:
            diff_reactive =  reactive_ocsp_end - old_ocsp_end
            diff_proactive = proactive_ocsp_end - old_ocsp_end
        return diff_reactive / tot_time, diff_proactive / tot_time, graph_tuple, diff_reactive, diff_proactive
    except Exception as e:
        a = 1

def analyze_zeek_output(file):
    f = open(file)
    d = json.load(f)
    arr_reactive = []
    arr_proactive = []

    arr_reactive_ac = []
    arr_proactive_ac = []

    for e in d:
        try:
            reactive_ratio, proactive_ratio, graph_tuple, diff_reactive, diff_proactive = analyze_single_entry(e)
            if reactive_ratio is not None:
                arr_reactive.append((reactive_ratio, graph_tuple))
                arr_reactive_ac.append(diff_reactive)
            if proactive_ratio is not None:
                arr_proactive.append((proactive_ratio, graph_tuple))
                arr_proactive_ac.append(diff_proactive)
        except Exception as err:
            a = 1
    return arr_reactive, arr_proactive, arr_reactive_ac, arr_proactive_ac


def analyze_init():
    store_dict = {}

    for mode in modes:
        for staple_mode in staple_modes:

            first_reactive_arr = []
            first_proactive_arr = []
            second_proactive_arr = []
            second_reactive_arr = []

            first_reactive_arr_ac = []
            first_proactive_arr_ac = []
            second_proactive_arr_ac = []
            second_reactive_arr_ac = []

            first_domains = 0
            second_domains = 0

            files = get_leaf_files("{}/{}/{}".format(result_path, mode, staple_mode))
            for file in files:
                segments = file.split("/")
                file_name = segments[-1]
                sub_segs = file_name.split("-")
                index_first = int(sub_segs[0])
                index_second = int(sub_segs[1][: -5])
                arr_reactive, arr_proactive, arr_reactive_ac, arr_proactive_ac  = analyze_zeek_output(file)

                if index_first < 30000:
                    first_domains += index_second - index_first + 1
                    first_reactive_arr += arr_reactive
                    first_proactive_arr += arr_proactive

                    first_reactive_arr_ac += arr_reactive_ac
                    first_proactive_arr_ac += arr_proactive_ac
                else:
                    second_domains += index_second - index_first + 1
                    second_reactive_arr += arr_reactive
                    second_proactive_arr += arr_proactive

                    second_reactive_arr_ac += arr_reactive_ac
                    second_proactive_arr_ac += arr_proactive_ac

            mother_str = "{}-{}".format(mode, staple_mode)
            store = {}
            store["first_reactive_arr"] = first_reactive_arr
            store["second_reactive_arr"] = second_reactive_arr
            store["first_proactive_arr"] = first_proactive_arr
            store["second_proactive_arr"] = second_proactive_arr

            store["first_reactive_arr_ac"] = first_reactive_arr_ac
            store["second_reactive_arr_ac"] = second_reactive_arr_ac
            store["first_proactive_arr_ac"] = first_proactive_arr_ac
            store["second_proactive_arr_ac"] = second_proactive_arr_ac

            store["f_domains"] = first_domains
            store["l_domains"] = second_domains

            store_dict[mother_str] = store

    with open("mother_dict.json", "w") as ouf:
        json.dump(store_dict, fp=ouf)

def mult(arr, p):
    d = []
    for e in arr:
        d.append(max(e * p, -100))
    return d

def draw_graphs():
    f = open("data/mother_dict.json")
    d = json.load(f)
    a = 1
    # a = 1

    f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/ocsp_simulation/data/mother_dict.json")
    d = json.load(f)

    cdf_multiple(
        [mult(d['cold-stapledon']['first_proactive_arr_ac'], 100), mult(d['cold-stapledon']['second_proactive_arr_ac'], 100)],
        ['Top', 'Bottom'], "CDF", "Percentage")

    tuple_list = []
    for e in d['warm-stapledon']['second_proactive_arr']:
        tuple = e[1]
        tuple_list.append(tuple)
        # dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
    tuple_list.sort()

    base_dns_list = []
    ocsp_dns_list = []
    ocsp_http_list = []
    base_tls_list = []
    tot_ocsp_overhead_list = []
    x_list = []
    x_list_master = []

    index = 1

    for tuple in tuple_list:
        dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
        # base_dns_list.append(base_dns)
        ocsp_dns_list.append(ocsp_dns)
        ocsp_http_list.append(ocsp_http)
        base_tls_list.append(base_tls)
        x_list.append(index)
        index += 1
        tot_ocsp_overhead_list.append(tot_ocsp_overhead)
        if index == 50:
            break

    for i in range(3):
        x_list_master.append(x_list)
    multiple_line_drawer(N=3, x_list=x_list_master, y_list=[ocsp_dns_list, ocsp_http_list, base_tls_list], label_list=["ocsp_dns_list", "ocsp_http_list", "base_tls_list"], title='xx')

analyze_init()
# analyze_second_step()
# draw_graphs()

















