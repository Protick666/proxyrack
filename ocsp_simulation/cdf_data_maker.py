import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.pyplot as plt

def histogram_maker_v2(counters, labels, x_title, y_title, title, shortened=False):
    import seaborn as sns
    sns.set()

    import matplotlib.pyplot as plt
    ans = []

    if not shortened:
        fig = plt.figure(figsize=(30, 10))
    else:
        fig = plt.figure(figsize=(10, 5))

    index = 0
    x = []
    y = []

    for counter in counters:
        for key in counter:
            ans.append((key, counter[key]))
        ans.sort()
        x_arr = [str(e[0]) for e in ans]
        y_arr = [e[1] for e in ans]
        y_sum = sum(y_arr)
        y_arr = [(e/y_sum) * 100 for e in y_arr]
        x.append(x_arr)
        y.append(y_arr)
        # plt.bar(x_arr, y_arr, edgecolor='black', label=labels[index])
        index += 1

    plt.bar(x, y, edgecolor='black', label=labels)
    plt.legend(loc='best')
    plt.title(title)
    plt.xlabel(x_title)
    plt.ylabel(y_title)
    plt.show()

def histogram_maker(counter, x_title, y_title, title, shortened=False):
    import seaborn as sns
    sns.set()

    import matplotlib.pyplot as plt
    ans = []
    if not shortened:
        fig = plt.figure(figsize=(10, 10))
    else:
        fig = plt.figure(figsize=(10, 5))
    for key in counter:
        ans.append((key, counter[key]))
    ans.sort()

    x_arr = [str(e[0]) for e in ans]
    y_arr = [e[1] for e in ans]
    # x_ticks = []
    # x_ticks_labels = []
    #
    # mod = 1
    #
    # cmp = [3600, 9000, 16200, 27000, 43200, 72000]
    # # for i in range(200000):
    # #     cmp.append(cmp[-1] + 30 * 60)
    # matched = 0
    # for index in range(len(x_arr)):
    #     e = x_arr[index]
    #     if abs(cmp[matched] - int(e)) < 100:
    #         x_ticks.append(index)
    #         x_ticks_labels.append("{} hours".format(cmp[matched]//3600))
    #         mod += 1
    #         matched += 1
    #         if matched >= len(cmp):
    #             break

    plt.bar(x_arr, y_arr, edgecolor='black')
    # plt.xticks(x_ticks, x_ticks_labels, rotation=80)
    plt.title(title)
    plt.xlabel(x_title)
    plt.ylabel(y_title)
    plt.show()
    #plt.savefig('ttl_result/histogram-{}.png'.format(title), bbox_inches="tight")
    #plt.clf()

def pie_chart_maker(values, labels):

    def autopct_format(values):
        def my_format(pct):
            total = sum(values)
            val = int(round(pct * total / 100.0))
            return '{:.1f}%\n({v:d})'.format(pct, v=val)

        return my_format

    import seaborn as sns
    sns.set()
    # labels = 'Random', 'Decreasing', 'Increasing', 'Regular'
    sizes = values
    explode = (0, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')
    plt.figure(figsize=(10, 10))
    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, labels=labels, autopct=autopct_format(sizes),
             startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # plt.savefig('graphs_final_3/pattern.png', bbox_inches="tight")
    # plt.clf()
    plt.show()

def multiple_line_drawer(N, x_list, y_list, label_list, x_ticks, tick_labels, title='.', marker='.', y_label=''):
    import seaborn as sns
    sns.set()

    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

    fig, ax = plt.subplots(figsize=(15, 8))

    for i in range(N):
        # y_lst_in_ms = [e * 1000 for e in y_list[i]]
        plt.plot(x_list[i], y_list[i], label=label_list[i], marker=marker)
    # plt.xlabel('Iterations')
    plt.ylabel(y_label)
    plt.legend(loc='best')

    # x_ticks = [e[0] for e in tick_index]
    # x_ticks_labels = [e[1] for e in tick_index]
    plt.xticks(x_ticks, tick_labels, rotation='60')

    plt.title(title)

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



def cdf_multiple_from_counter(x_to_counters, label_lst, title, x_label):
    import seaborn as sns
    sns.set()

    fig, ax = plt.subplots(figsize=(12, 8))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.xlabel(x_label)
    plt.ylabel("CDF")
    plt.title(title)

    index = 0
    # .sort()

    for counter in x_to_counters:
        x_list = list(counter.keys())
        x_list.sort()
        label = label_lst[index]
        arr = x_list
        y = []
        temp = 0
        tot = 0
        # 630938650
        for e in arr:
            tot += counter[e]
        for e in arr:
            temp += counter[e]
            y.append(temp/tot)
        a = 1
        plt.plot(x_list, y, marker='.', label=label)
        index += 1
    plt.legend(
        loc='best', shadow=True,
    )
    plt.show()
    plt.clf()

def cdf_multiple(x_list, label_lst, title, x_label):
    import seaborn as sns
    sns.set()

    fig, ax = plt.subplots(figsize=(20, 6))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.xlabel(x_label)
    plt.ylabel("CDF")
    plt.title(title)

    index = 0
    for lst in x_list:
        label = label_lst[index]
        arr = lst
        arr_waste = [e for e in arr if e > 2000]
        arr = [e for e in arr if e < 2000]
        # arr_waste = [e for e in arr if e > 2000]
        N = len(arr)
        data = np.array(arr)
        x = np.sort(data)
        y = np.arange(N) / float(N)
        plt.plot(x, y, marker='.', label=label)
        index += 1
        print("len waste {}".format(len(arr_waste)))
    plt.legend(
        loc='best', shadow=True,
    )
    plt.show()
    plt.clf()


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


def analyze_xxxx():
    f = open("amulgum.json")
    d = json.load(f)
    tot_tls  = 0
    tot_ocsp = 0
    server_set = set()

    for e in d:
        server_name = e[-1]
        ocsp_1 = e[-3]
        ocsp_2 = e[-2]

        if "demdex" in server_name or "mozilla" in server_name:
            continue

        tot_tls += 1
        server_set.add(server_name)
        if ocsp_1 is not None and ocsp_2 is not  None:
            tot_ocsp += 1

    print(tot_tls, len(server_set), tot_ocsp)


analyze_xxxx()

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
            return 0, 0, graph_tuple, 0, 0, 0, 0
        else:
            diff_reactive =  reactive_ocsp_end - old_ocsp_end
            diff_proactive = proactive_ocsp_end - old_ocsp_end
        return diff_reactive / tot_time, diff_proactive / tot_time, graph_tuple, diff_reactive, diff_proactive, old_ocsp_end - established_time, (old_ocsp_end - established_time) / tot_time
    except Exception as e:
        a = 1

def analyze_zeek_output(file):
    f = open(file)
    d = json.load(f)
    arr_reactive = []
    arr_proactive = []

    arr_reactive_ac = []
    arr_proactive_ac = []

    penalty_arr = []
    penalty_normalized_arr = []

    for e in d:
        try:
            reactive_ratio, proactive_ratio, graph_tuple, diff_reactive, diff_proactive, penalty, penalty_normalized = analyze_single_entry(e)

            penalty_arr.append(penalty)
            penalty_normalized_arr.append(penalty_normalized)

            if reactive_ratio is not None:
                arr_reactive.append((reactive_ratio, graph_tuple))
                arr_reactive_ac.append(diff_reactive)
            if proactive_ratio is not None:
                arr_proactive.append((proactive_ratio, graph_tuple))
                arr_proactive_ac.append(diff_proactive)
        except Exception as err:
            a = 1
    return arr_reactive, arr_proactive, arr_reactive_ac, arr_proactive_ac, penalty_arr, penalty_normalized_arr


def coalesce_entries():

    files = get_leaf_files("/home/protick/proxyrack/ocsp_simulation/simulation_results/nsec")
    arr = []
    for file in files:
        print("Analyzing file ",file)
        f = open(file)
        d = json.load(f)
        arr = arr + d

    with open("amulgum.json", "w") as ouf:
        json.dump(arr, fp=ouf)


# coalesce_entries()

def one_million_analyzer():
    f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/nsec_exp/data/ocsp_req.json")
    d = json.load(f)
    req_time = [int(e * 1000) for e in d]
    from collections import defaultdict
    counter = defaultdict(lambda : 0)
    for e in req_time:
        counter[e] += 1

    cdf_multiple([req_time], ['OCSP response time'], 'OCSP response', 'Response time in milliseconds')



one_million_analyzer()

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

            first_penalty_arr = []
            first_penalty_normalized_arr = []
            second_penalty_arr = []
            second_penalty_normalized_arr = []

            first_domains = 0
            second_domains = 0

            files = get_leaf_files("{}/{}/{}".format(result_path, mode, staple_mode))
            for file in files:
                segments = file.split("/")
                file_name = segments[-1]
                sub_segs = file_name.split("-")
                index_first = int(sub_segs[0])
                index_second = int(sub_segs[1][: -5])
                arr_reactive, arr_proactive, arr_reactive_ac, arr_proactive_ac, penalty_arr, penalty_normalized_arr  = analyze_zeek_output(file)

                if index_first < 30000:
                    first_domains += index_second - index_first + 1
                    first_reactive_arr += arr_reactive
                    first_proactive_arr += arr_proactive

                    first_reactive_arr_ac += arr_reactive_ac
                    first_proactive_arr_ac += arr_proactive_ac

                    first_penalty_arr += penalty_arr
                    first_penalty_normalized_arr += penalty_normalized_arr
                else:
                    second_domains += index_second - index_first + 1
                    second_reactive_arr += arr_reactive
                    second_proactive_arr += arr_proactive

                    second_reactive_arr_ac += arr_reactive_ac
                    second_proactive_arr_ac += arr_proactive_ac

                    second_penalty_arr += penalty_arr
                    second_penalty_normalized_arr += penalty_normalized_arr

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

            store["first_penalty_arr"] = first_penalty_arr
            store["first_penalty_normalized_arr"] = first_penalty_normalized_arr
            store["second_penalty_arr"] = second_penalty_arr
            store["second_penalty_normalized_arr"] = second_penalty_normalized_arr

            store["f_domains"] = first_domains
            store["l_domains"] = second_domains

            store_dict[mother_str] = store

    with open("mother_dict.json", "w") as ouf:
        json.dump(store_dict, fp=ouf)

def mult(arr, p, constaint=True):
    d = []
    arr = arr
    for e in arr:
        a = 1
        try:
            if constaint:
                d.append(min(e[0] * p, 300))
            else:
                d.append(e[0] * p)
        except Exception as ee:
            a = 1
        # d.append(e * p)
    return d

def draw_graphs():
    f = open("data/mother_dict.json")
    d = json.load(f)
    a = 1
    normalized_arr = d['normal-stapledon']['first_penalty_normalized_arr']
    penalty_arr = d['normal-stapledon']['first_penalty_arr']

    ocsp_http_call_arr = []
    for e in d['normal-stapledon']['second_proactive_arr']:
        dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = e[1]
        ocsp_http_call_arr.append(ocsp_http)
    cdf_multiple([mult(ocsp_http_call_arr, 1000, constaint=False)], ['OCSP response time'],
                 "OCSP response time (milliseconds)", "milliseconds")

    cdf_multiple([mult(penalty_arr, 1000, constaint=False)], ['OCSP overhead'],
                 "OCSP Overhead in TLS connections (milliseconds)", "milliseconds")
    cdf_multiple([mult(normalized_arr, 100, constaint=True)], ['OCSP overhead percentage '],
                 "OCSP Overhead ratio", "OCSP overhead percentage")


    # a = 1
    # return

    f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/ocsp_simulation/data/mother_dict.json")
    d = json.load(f)

    # cdf_multiple(
    #     [mult(d['warm-stapledon']['first_proactive_arr'], 100), mult(d['warm-stapledon']['second_proactive_arr'], 100),
    #      mult(d['cold-stapledon']['first_proactive_arr'], 100), mult(d['cold-stapledon']['second_proactive_arr'], 100)],
    #     ['Warm Cache Top 5k', 'Warm Cache Bottom 5k', 'Cold Cache Top 5k', 'Cold Cache Bottom 5k'], "CDF", "Percentage")

    a = 1
    cdf_multiple(
        [mult(d['warm-stapledon']['first_proactive_arr'], 100), mult(d['warm-stapledon']['second_proactive_arr'], 100)],
        ['Warm Cache Top 5k', 'Warm Cache Bottom 5k'], "CDF", "Percentage")

    # tuple_list = []
    #
    # for e in d['warm-stapledon']['second_proactive_arr']:
    #     tuple = e[1]
    #     tuple_list.append(tuple)
    #     # dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
    #
    # tuple_list.sort()
    # base_dns_list = []
    # ocsp_dns_list = []
    # ocsp_http_list = []
    # base_tls_list = []
    # tot_ocsp_overhead_list = []
    # x_list = []
    # x_list_master = []
    #
    # index = 1
    #
    # for tuple in tuple_list:
    #     dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
    #     # base_dns_list.append(base_dns)
    #     ocsp_dns_list.append(ocsp_dns)
    #     ocsp_http_list.append(ocsp_http)
    #     base_tls_list.append(base_tls)
    #     x_list.append(index)
    #     index += 1
    #     tot_ocsp_overhead_list.append(tot_ocsp_overhead)
    #     if index == 50:
    #         break
    #
    # for i in range(3):
    #     x_list_master.append(x_list)
    #
    # multiple_line_drawer(N=3, x_list=x_list_master, y_list=[ocsp_dns_list, ocsp_http_list, base_tls_list], label_list=["ocsp_dns_list", "ocsp_http_list", "base_tls_list"], title='xx')



def draw_graphs_v2():
    # f = open("data/mother_dict.json")
    # d = json.load(f)
    # a = 1
    # # a = 1

    f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/ocsp_simulation/data/mother_dict.json")
    d = json.load(f)
    # dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name
    # cdf_multiple(
    #     [mult(d['warm-stapledon']['first_proactive_arr'], 100), mult(d['warm-stapledon']['second_proactive_arr'], 100),
    #      mult(d['cold-stapledon']['first_proactive_arr'], 100), mult(d['cold-stapledon']['second_proactive_arr'], 100)],
    #     ['Warm Cache Top 5k', 'Warm Cache Bottom 5k', 'Cold Cache Top 5k', 'Cold Cache Bottom 5k'], "CDF", "Percentage")

    tuple_list_warm_first = []
    tuple_list_warm_second = []

    for e in d['warm-stapledon']['second_proactive_arr']:
        tuple = e[1]
        tuple_list_warm_second.append(tuple)

    for e in d['warm-stapledon']['first_proactive_arr']:
        tuple = e[1]
        tuple_list_warm_first.append(tuple)
        # dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple

    tuple_list_warm_first.sort()
    tuple_list_warm_second.sort(reverse=True)

    # base_dns_list = []
    # ocsp_dns_list = []
    # ocsp_http_list = []
    # base_tls_list = []
    # tot_ocsp_overhead_list = []

    x_list = []
    x_list_first = []
    x_list_second = []

    ocsp_http_list_second = []
    base_tls_list_second = []
    ocsp_http_list_first = []
    base_tls_list_first = []

    index = 1
    for tuple in tuple_list_warm_first:
        dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
        # base_dns_list.append(base_dns)
        ocsp_http_list_first.append(ocsp_http)
        base_tls_list_first.append(base_tls)

        x_list_first.append(index)
        index += 1
        if index == 100:
            break

    index = 1
    for tuple in tuple_list_warm_second:
        dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead = tuple
        # base_dns_list.append(base_dns)

        ocsp_http_list_second.append(ocsp_http)
        base_tls_list_second.append(base_tls)

        #x_list_first.append(index)
        index += 1
        if index == 100:
            break

    for i in range(2):
        x_list.append(x_list_first)

    # multiple_line_drawer(N=2, x_list=x_list, y_list=[ocsp_http_list_second, base_tls_list_second, ocsp_http_list_first, base_tls_list_first], label_list=["OCSP HTTP response time - Bottom 5k", "OCSP TLS handshake time - Bottom 5k", "OCSP HTTP response time - Top 5k", "OCSP TLS handshake time - Top 5k"], title='xx')
    # multiple_line_drawer(N=2, x_list=x_list, y_list=[ocsp_http_list_second, ocsp_http_list_first], label_list=["OCSP HTTP response time - Bottom 5k", "OCSP HTTP response time - Top 5k"], title='xx')

    multiple_line_drawer(N=2, x_list=x_list, y_list=[base_tls_list_second, base_tls_list_first], label_list=["OCSP TLS handshake time - Bottom 5k", "OCSP TLS handshake time - Top 5k"], title='xx')


def process_data(d):
    for key in d:
        print(key, len(d[key]), sum(d[key]))

def draw_nsec_graph():
    # def cdf_multiple(x_list, label_lst, title, x_label):
    f = open("../ccadb/remote_data/cdf_data_global.json")
    d = json.load(f)
    a = 1
    x_list = [d]

    label_list = ["Overall"]

    #keys = ['INTERNET SECURITY RESEARCH GROUP', 'DIGICERT', 'GLOBALSIGN NV', 'GODADDY', 'IDENTRUST SERVICES, LLC', 'GOOGLE TRUST SERVICES LLC']

    # process_data(d)
    # return

    # for key in keys:
    #     x_list.append(d[key])
    #     label_list.append(key)

        # for nsec in d['ans_dict']:
        #     x_list.append(d['ans_dict'][nsec])
        #     label_list.append(str(nsec))

    cdf_multiple(x_list, label_list, 'CDF', 'Number of serials per NSEC')
    # cdf_multiple([d['ans_dict_selective']['2'], d['ans_dict_selective']['3'], d['ans_dict_selective']['300000']], ['1000', '10000','100000'], 'CDF', 'Number of serials per NSEC (selective)')

# draw_nsec_graph()
# draw_graphs()
# analyze_second_step()
# draw_graphs()
# draw_graphs_v2()

















