import json
import random

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.pyplot as plt
from multiprocessing.dummy import Pool as ThreadPool

def get_base_url_curtailed(url):
    ocsp_url_base = url
    if url.startswith("http://"):
        ocsp_url_base = url[7:]
    if "/" in ocsp_url_base:
        ocsp_url_base = ocsp_url_base[0: ocsp_url_base.find("/")]
    segments = ocsp_url_base.split(".")
    if len(segments) >= 3:
        return "{}.{}".format(segments[-2], segments[-1])
    else:
        return ocsp_url_base


def box_plot(cdn_to_arr, title, label_to_is_cdn):
    import seaborn as sns
    sns.set()
    data_to_plot = []
    labels = []
    import statistics
    temp = []
    for cdn in cdn_to_arr:
        temp.append((statistics.median(cdn_to_arr[cdn]), cdn_to_arr[cdn], cdn))

    temp.sort()

    indexes_of_cdn = []

    ind = 0
    for tup in temp:
        data_to_plot.append(tup[1])
        labels.append(tup[2])
        if label_to_is_cdn[tup[2]] == 3:
            indexes_of_cdn.append(ind)
        ind += 1

    fig = plt.figure(1, figsize=(15, 13))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

    # Create an axes instance
    ax = fig.add_subplot(111)
    a = 1

    bp = ax.boxplot(data_to_plot, patch_artist=True, showfliers=False, whis=0)

    ## change outline color, fill color and linewidth of the boxes
    ind = 0
    for box in bp['boxes']:
        # change outline color
        box.set(color='#7570b3', linewidth=2)
        # change fill color
        if ind in indexes_of_cdn:
            box.set(facecolor='#6b103e')
        else:
            box.set(facecolor='#1b9e77')

        ind += 1

    ## change color and linewidth of the whiskers
    for whisker in bp['whiskers']:
        whisker.set(color='#7570b3', linewidth=2)

    ## change color and linewidth of the caps
    for cap in bp['caps']:
        cap.set(color='#7570b3', linewidth=2)

    ## change color and linewidth of the medians
    for median in bp['medians']:
        median.set(color='#b2df8a', linewidth=2)

    ## change the style of fliers and their fill
    for flier in bp['fliers']:
        flier.set(marker='o', color='#e7298a', alpha=0.5)

    ax.set_xticklabels(labels, rotation=45)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()

    ax.set_ylabel('milliseconds')

    import matplotlib.patches as mpatches

    # if ind in indexes_of_cdn:
    #     box.set(facecolor='#6b103e')
    # else:
    #     box.set(facecolor='#1b9e77')

    patch1 = mpatches.Patch(color='#6b103e', label='CDN')
    patch2 = mpatches.Patch(color='#1b9e77', label='Non-CDN')

    all_handles = (patch1, patch2)

    leg = ax.legend(handles=all_handles)

    ax.add_artist(leg)

    plt.title(title)
    plt.show()

    return labels

def get_filtered_errors(arr):
    temp = []
    # 'non-200-502' ?? 'decode-str-Unable to load OCSP response'
    skip_list = ['non-200-407', 'Response payload is not completed', 'Server disconnected',
                 '[Errno 104] Connection reset by peer', '502, message=',
                 'non-200-502', 'decode-str-Unable to load OCSP response', 'timeout']

    for e in arr:
        skip = False
        for st in skip_list:
            if st.lower() in e.lower():
                skip = True
        if not skip:
            temp.append(e)

    return temp


def lum_analyzer():
    f = open("../nsec_exp/data/lum_summary.json")
    mother_dict = json.load(f)

    f = open("../nsec_exp/data/lum_err_summary.json")
    err_summ = json.load(f)

    f = open("data/origin.json")
    origin = json.load(f)

    from collections import defaultdict
    url_to_response_list = defaultdict(lambda : list())
    # url_to_serial = defaultdict(lambda: set())

    f = open('data/url_counter.json')
    d = json.load(f)
    d.sort(key=lambda x: x[1], reverse=True)


    visited = {}

    base_to_org = {}
    org_to_type = {}

    # org_to_good = defaultdict(lambda: 0)
    # org_to_bad = defaultdict(lambda: 0)

    for url in origin:
        base_url = get_base_url_curtailed(url)
        org = origin[url]['org']
        base_to_org[base_url] = org
        org_to_type[org] = origin[url]['type']

    # for url in err_summ:
    #     base_url = get_base_url_curtailed(url)
    #
    #     if base_url not in base_to_org:
    #         continue
    #
    #     org = base_to_org[base_url]
    #     t = [e[2] for e in err_summ[url]]
    #     t = get_filtered_errors(t)
    #     org_to_bad[org] += len(t)

    org_to_response_all = defaultdict(lambda: list())
    org_to_response_top = defaultdict(lambda: list())

    for tup in d:
        url = tup[-1]
        # TODO
        # if 'sectigo' in url:
        #     continue

        b_url = get_base_url_curtailed(url)

        if b_url not in base_to_org:
            continue
        org = base_to_org[b_url]

        if 'cloudflare' in org.lower() and 'globalsign' not in b_url.lower():
            continue

        temp_lst = []

        for element in mother_dict[url]:
            asn, serial, delegated_response, response_time_local, response_time_lum = element
            temp_lst.append((response_time_lum, asn))

        if org not in visited:
            org_to_response_top[org] = org_to_response_top[org] + temp_lst

        visited[org] = 1

        org_to_response_all[org] = org_to_response_all[org] + temp_lst
        # org_to_good[org] += len(temp_lst)

    with open("data/org_to_response_top_with_asn.json", "w") as ouf:
        json.dump(org_to_response_top, fp=ouf)

    with open("data/org_to_response_all_with_asn.json", "w") as ouf:
        json.dump(org_to_response_all, fp=ouf)

    # with open("data/org_to_response_stats.json", "w") as ouf:
    #     json.dump({
    #         "org_to_good": org_to_good,
    #         "org_to_bad": org_to_bad
    #     }, fp=ouf)

    a = 1


def lum_analyzer_to_region():
    print("yo")
    f = open('data/org_to_response_all_with_asn.json')
    d = json.load(f)

    from collections import defaultdict
    from routeview_analyzer import get_asn_to_cn

    f = open("data/cn_region.json")
    cn_region = json.load(f)

    cn_to_region = {}
    for e in cn_region:
        cn_to_region[e['alpha-2']] = e['region']



    org_to_cn_to_responses = defaultdict(lambda : defaultdict(lambda : list()))
    org_to_region_to_responses = defaultdict(lambda: defaultdict(lambda: list()))

    for org in d:
        for e in d[org]:
            res = e[0][0]
            asn = int(e[1])
            cn = get_asn_to_cn(asn)
            org_to_cn_to_responses[org][cn].append(res)

            try:
                region = cn_to_region[cn.upper()]
            except:
                region = "xxx"
            org_to_region_to_responses[org][region].append(res)

    with open("data/org_to_cn_to_response.json", "w") as ouf:
        json.dump(org_to_cn_to_responses, fp=ouf)
    with open("data/org_to_region_to_responsese.json", "w") as ouf:
        json.dump(org_to_region_to_responses, fp=ouf)


def get_label_and_is_cdn(label):
    if 't-systems' in label.lower():
        return 'T-Systems', 1
    cdn_hint = ['Fastly', 'Akamai', 'Verizon', 'Microsoft', 'Cloudflare', 'Amazon', 'Alibaba']
    for e in cdn_hint:
        if e.lower() in label.lower():
            '''
                1 -> other
                3 -> CDN
            '''
            if e == 'Microsoft':
                return 'Azure CDN', 3
            if e == 'Amazon':
                return 'Cloudfront', 3
            return e, 3
    return label, 1

def box_plot_of_lum(region):
    from collections import defaultdict
    f = open("data/org_to_region_to_responsese.json")
    d = json.load(f)
    urls = list(d.keys())
    # urls = random.sample(urls, 40)
    # urls = urls[: 10] + urls[-10: ]
    box_d = defaultdict(lambda : list())
    label_to_is_cdn = {}

    f = open("data/org_to_response_stats.json")
    org_to_response_stats = json.load(f)

    for url in urls:
        lb = url
        if 'cloudfront' in url.lower():
            continue
        if 'amazon' in url.lower() and url != 'Amazon':
            continue

        label, cdn = get_label_and_is_cdn(url)
        if len(label.split(" ")) > 2:
            label = label.split(" ")[0] + " " + label.split(" ")[1]

        label_to_is_cdn[label] = cdn

        box_d[label] = box_d[label] + [e for e in d[url][region] if e <= 2000]

        # box_d[url] = [e for e in box_d[url] if e <= 2000]

    labels = box_plot(box_d, "Boxplot of response time - {}".format(region), label_to_is_cdn)

    # for label in labels:
    #     org_to_good = org_to_response_stats['org_to_good'][label]
    #     org_to_bad = org_to_response_stats['org_to_bad'][label]
    #     print(label, (org_to_bad / (org_to_good + org_to_bad)) * 100)

def lum_error():
    f = open("../nsec_exp/data/lum_err_summary.json")
    d = json.load(f)
    a = 1
    from collections import defaultdict
    err_set = defaultdict(lambda : 0)
    for url in d:
        for e in d[url]:
            err_set[e[2]] += 1
    arr = []
    for e in err_set:
        arr.append((err_set[e], e))
    arr.sort(reverse=True)
    a = 1
    # 'non-200-502' ?? 'decode-str-Unable to load OCSP response'
    skip_list = ['non-200-407','Response payload is not completed', 'Server disconnected', '[Errno 104] Connection reset by peer', '502, message=']
#
box_plot_of_lum("Asia")
box_plot_of_lum("Americas")
# lum_analyzer()
# lum_analyzer_to_region()
# lum_error()




def stat():
    f = open('data/url_counter.json')
    d = json.load(f)
    d.sort(key=lambda x: x[1], reverse=True)

    req = 0
    serial = 0
    for e in d:
        req += e[0]
        serial += e[1]
    print(req, serial)

# stat()
def lum_basic():
    f = open('data/url_counter.json')
    d = json.load(f)
    d.sort(key=lambda x: x[1], reverse=True)
    a = 1

    # ocsp_url_to_tuple_list[url].append(
    #     (asn, serial, delegated_response, time_end - time_start, response_time_lum))
# lum_analyzer()
# lum_analyzer()
# box_plot_of_lum()
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
        arr = [e * 100 for e in arr]

        # arr_waste = [e for e in arr if e > 2000]
        arr = [e for e in arr if -1000 <= e <= 1000]
        # arr_waste = [e for e in arr if e > 2000]

        N = len(arr)
        data = np.array(arr)
        x = np.sort(data)
        y = np.arange(N) / float(N)
        plt.plot(x, y, marker='.', label=label)
        index += 1
        # print("len waste {}".format(len(arr_waste)))
    plt.legend(
        loc='best', shadow=True,
    )

    plt.savefig('graph_pre_v4/{}.png'.format(title), bbox_inches="tight")

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

    ocsp_req_time = []
    ocsp_over_head = []
    tls_time = []

    for e in d:
        dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name = e


        if "demdex" in server_name or "mozilla" in server_name:
            continue

        tot_tls += 1

        server_set.add(server_name)

        if ocsp_1 is not None and ocsp_2 is not None:
            tot_ocsp += 1
            ocsp_req_time.append(ocsp_2 - ocsp_1)
            over_head = 0
            if ocsp_2 > established_time:
                over_head = ocsp_2 - established_time
            ocsp_over_head.append(over_head)
            tls_time.append(established_time - server_hello_time)

    print(tot_tls, len(server_set), tot_ocsp)
    with open("ocsp_initial_graphs.json", "w") as ouf:
        json.dump({
            "ocsp_over_head": ocsp_over_head,
            "ocsp_req_time": ocsp_req_time,
            "tls_time": tls_time
        }, fp=ouf)


# analyze_xxxx()

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

ans_lst = []
def analyze_single_entry_new(tuple):
    try:
        global ans_lst
        # print("Inside")
        e, index = tuple
        # dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name, meta, _ = e
        dns_start, dns_end, client_hello_time, server_hello_time, change_cipher_time_client, change_cipher_time_server, established_time, encrypted_data_time_app, ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, server_name = e

        if "demdex" in server_name or "mozilla" in server_name:
            return None

        things_needed = [ocsp_dns_1, ocsp_dns_2, ocsp_1, ocsp_2, established_time, client_hello_time, dns_start, dns_end]
        for e in things_needed:
            if e is None:
                return None

        base_dns = dns_end - dns_start
        ocsp_dns = ocsp_dns_2 - ocsp_dns_1
        ocsp_http = ocsp_2 -ocsp_1
        base_tls = established_time - client_hello_time
        tot_ocsp_overhead = ocsp_2 - ocsp_dns_1

        for base_dns_mode in ["hit", "normal"]:
            for ocsp_dns_mode in ["hit", "normal"]:
                for simulation_dns_mode in ["hit", "normal"]:

                    accumulated_str = "{}-{}-{}".format(base_dns_mode, ocsp_dns_mode, simulation_dns_mode)

                    if accumulated_str == 'hit-hit-hit':

                        base_dns_start_new = max(dns_end - .002, dns_start)
                        ocsp_diff = 0
                        if ocsp_dns > .002:
                            ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + .002
                        simulated_cname_ocsp_2 = base_dns_start_new + .002

                    if accumulated_str == 'hit-hit-normal':

                        base_dns_start_new = max(dns_end - .002, dns_start)
                        ocsp_diff = 0
                        if ocsp_dns > .002:
                            ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + ocsp_dns
                        simulated_cname_ocsp_2 = base_dns_start_new + ocsp_dns

                    if accumulated_str == 'hit-normal-hit':

                        base_dns_start_new = max(dns_end - .002, dns_start)
                        ocsp_diff = 0
                        # if ocsp_dns > .002:
                        #     ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + .002
                        simulated_cname_ocsp_2 = base_dns_start_new + .002

                    if accumulated_str == 'normal-hit-hit':

                        base_dns_start_new = dns_start
                        ocsp_diff = 0
                        if ocsp_dns > .002:
                            ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + .002
                        simulated_cname_ocsp_2 = base_dns_start_new + .002

                    if accumulated_str == 'hit-normal-normal':
                        base_dns_start_new = max(dns_end - .002, dns_start)
                        ocsp_diff = 0
                        # if ocsp_dns > .002:
                        #     ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + ocsp_dns
                        simulated_cname_ocsp_2 = base_dns_start_new + ocsp_dns

                    if accumulated_str == 'normal-hit-normal':
                        base_dns_start_new = dns_start
                        ocsp_diff = 0

                        if ocsp_dns > .002:
                            ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + ocsp_dns
                        simulated_cname_ocsp_2 = base_dns_start_new + ocsp_dns

                    if accumulated_str == 'normal-normal-hit':
                        base_dns_start_new = dns_start
                        ocsp_diff = 0
                        # if ocsp_dns > .002:
                        #     ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + .002
                        simulated_cname_ocsp_2 = base_dns_start_new + .002

                    if accumulated_str == 'normal-normal-normal':
                        base_dns_start_new = dns_start
                        ocsp_diff = 0
                        # if ocsp_dns > .002:
                        #     ocsp_diff = ocsp_dns - .002
                        new_ocsp_2 = ocsp_2 - ocsp_diff

                        simulated_serial_ocsp_2 = ocsp_dns_1 + ocsp_dns
                        simulated_cname_ocsp_2 = base_dns_start_new + ocsp_dns


        # graph_tuple = (dns_start, base_dns, ocsp_dns, ocsp_http, base_tls, tot_ocsp_overhead)

                    old_ocsp_end = new_ocsp_2
                    tot_time_wrt_hello = encrypted_data_time_app - client_hello_time
                    tot_time_wrt_dns = encrypted_data_time_app - base_dns_start_new


                    mom =  {
                        "mode": accumulated_str,
                        "tot_time_wrt_hello": tot_time_wrt_hello,
                        "tot_time_wrt_dns": tot_time_wrt_dns,
                        "ocsp_end": new_ocsp_2,
                        "encrypted_data_time_app": encrypted_data_time_app,
                        "established_time": established_time,
                        "simulated_serial_ocsp_2": simulated_serial_ocsp_2,
                        "simulated_cname_ocsp_2": simulated_cname_ocsp_2
                    }

                    ans_lst.append(mom)
        print("Done with ".format(index))

    except Exception as e:
        print("{} - {}".format(index, e))
        return None

def analyze_new_file():
    f = open("/Users/protick.bhowmick/ocsp_simulation/amulgum.json")
    d = json.load(f)
    print("Loaded file {}".format(len(d)))


    lines_with_number = []

    index = 0
    for e in d:
        lines_with_number.append((e, index))
        index += 1

    print("Loaded file again")

    pool = ThreadPool(50)
    results = pool.map(analyze_single_entry_new, lines_with_number)
    pool.close()
    pool.join()

    # from multiprocessing import Pool
    # with Pool() as pool:
    #     for result in pool.imap_unordered(analyze_single_entry_new, lines_with_number):
    #         ans_lst.append(result)

    with open("data/ans_lst.json", "w") as ouf:
        json.dump(ans_lst, fp=ouf)

    # for e in d:
    #     result_tuple = analyze_single_entry_new(e)

# analyze_new_file()

def cdf_of_diff_modes():
    from collections import defaultdict
    mode_to_sub_mode_to_arr = defaultdict(lambda: defaultdict(lambda : list()))

    # p =  {"mode": "hit-hit-hit",
    #       "tot_time_wrt_hello": 0.3312098979949951,
    #       "tot_time_wrt_dns": 0.36630988121032715,
    #       "ocsp_end": 1679009829.428184,
    #       "encrypted_data_time_app": 1679009829.516909,
    #       "established_time": 1679009829.210116,
    #       "simulated_serial_ocsp_2": 1679009829.293147,
    #       "simulated_cname_ocsp_2": 1679009829.152599}

    f = open("data/ans_lst.json")
    d = json.load(f)
    for e in d:
        mode = e['mode']
        tot_time_wrt_hello = e['tot_time_wrt_hello']
        tot_time_wrt_dns = e['tot_time_wrt_dns']
        ocsp_end = e['ocsp_end']
        encrypted_data_time_app = e['encrypted_data_time_app']
        established_time = e['established_time']
        simulated_serial_ocsp_2 = e['simulated_serial_ocsp_2']
        simulated_cname_ocsp_2 = e['simulated_cname_ocsp_2']

        end_modes = [simulated_serial_ocsp_2, simulated_cname_ocsp_2]
        end_modes_str = ['By serial', 'By Cname']

        ii = 0
        for end_mode in end_modes:
            str_sub = end_modes_str[ii]
            ii += 1
            ocsp_simulated_end = end_mode

            if ocsp_end <= established_time and ocsp_simulated_end <= established_time:
                delta = 0
            elif ocsp_end <= established_time < ocsp_simulated_end:
                delta = ocsp_simulated_end - established_time
            elif ocsp_end > established_time >= ocsp_simulated_end:
                delta = established_time - ocsp_end
            elif ocsp_end > established_time and ocsp_simulated_end > established_time:
                delta = ocsp_simulated_end - ocsp_end

            mode_to_sub_mode_to_arr[mode][str_sub].append((delta/tot_time_wrt_hello, delta/tot_time_wrt_dns))

    with open("cdf_all_modes.json", "w") as ouf:
        json.dump(mode_to_sub_mode_to_arr, fp=ouf)

# cdf_of_diff_modes()


def draw_cdf_of_simulations():
    print("here")
    f = open("cdf_all_modes.json")
    d = json.load(f)
    a = 1

    t = ['hit', 'normal']
    arr = []
    for x in t:
        for y in t:
            for z in t:
                arr.append("{}-{}-{}".format(x, y, z))
    a = 1

    for element in arr:
        for p in ["By serial"]:
            arr = d[element][p]
            arr_1 = [e[0] for e in arr]
            arr_2 = [e[1] for e in arr]
            cdf_multiple([arr_1], ["CDF"], "{}".format(element), "(%) gain")
            # cdf_multiple([arr_2], ["CDF"], "{} - {} - with respect to DNS".format(element, p), "(%) gain")


    # for element in arr:
    #     for p in ["By Cname", "By serial"]:
    #         arr = d[element][p]
    #         arr_1 = [e[0] for e in arr]
    #         arr_2 = [e[1] for e in arr]
    #         cdf_multiple([arr_1], ["CDF"], "{} - {}".format(element, p), "(%) gain")
    #         # cdf_multiple([arr_2], ["CDF"], "{} - {} - with respect to DNS".format(element, p), "(%) gain")


# draw_cdf_of_simulations()
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
    #f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/nsec_exp/data/ocsp_req.json")
    f = open("/Users/protick.bhowmick/PriyoRepos/proxyRack/nsec_exp/data/ocsp_initial_graphs.json")
    d = json.load(f)
    # req_time = [int(e * 1000) for e in d]
    over_head = d['ocsp_over_head']
    ocsp_req_time = d['ocsp_req_time']
    tls_time = d['tls_time']

    over_head = [int(e * 1000) for e in over_head]
    ocsp_req_time = [int(e * 1000) for e in ocsp_req_time]
    tls_time = [int(e * 1000) for e in tls_time]

    from collections import defaultdict
    counter = defaultdict(lambda : 0)
    for e in over_head:
        counter[e] += 1

    cdf_multiple([over_head], ['OCSP overhead'], 'OCSP response', 'Overhead time in milliseconds')
    cdf_multiple([ocsp_req_time], ['OCSP response time'], 'OCSP response time vs TLS handshsake time', 'Milliseconds')



# one_million_analyzer()

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
    # f = open("../ccadb/remote_data/cdf_data_global.json")
    f = open("../ccadb/data/cdf_data.json")
    d = json.load(f)

    tot_nssec = 0
    tot_certs = 0

    for e in d:
        if e[0] == "-1":
            continue
        tot_nssec += 1
        tot_certs += e[1]

    print(tot_nssec, tot_certs)

    from collections import defaultdict
    val_to_count = defaultdict(lambda : 0)

    for tup in d:
        id, cnt = tup
        val_to_count[cnt] += 1

    cdf_multiple_from_counter([val_to_count], ["cdf"], "cdf", "count")



    #cdf_multiple(x_list, label_list, 'CDF', 'Number of serials per NSEC')
    # cdf_multiple([d['ans_dict_selective']['2'], d['ans_dict_selective']['3'], d['ans_dict_selective']['300000']], ['1000', '10000','100000'], 'CDF', 'Number of serials per NSEC (selective)')

# draw_nsec_graph()
# 570746 241621779

'''
    

'''

# draw_nsec_graph()
# draw_graphs()
# analyze_second_step()
# draw_graphs()
# draw_graphs_v2()

















