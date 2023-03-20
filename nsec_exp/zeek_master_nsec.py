import time
from pathlib import Path
import subprocess
from multiprocessing.dummy import Pool as ThreadPool


def get_leaf_files(path):
    # print(path)
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            print(file)
            list_of_files.append(os.path.join(root, file))
    return list_of_files


def execute_cmd(command):
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    # time.sleep(5)
    return output, error


modes = ['warm', 'cold', 'normal']


# /opt/zeek/bin/zeek -r  files/test1.pcapng  ssl_ext_v1.zeek  ocsp_ext_v1.zeek http_ext_v1.zeek LogAscii::use_json=T SSL::disable_analyzer_after_detection=F  LogAscii::logdir=files


def zeekify(file):
    global parsed_ranges
    # # /cold-stapledoff-999701-999800.pcap
    print("Started processing {}".format(file))
    end_str = file.split("/")[-1]
    segments = end_str.split("-")
    st_index = segments[2]
    end_index = segments[3][0: -5]

    nsec_range = "{}-{}".format(st_index, end_index)
    if nsec_range in parsed_ranges:
        print("Already Done")
        return

    dump_directory = "zeek_logs/nsec/{}-{}/".format(st_index, end_index)
    Path(dump_directory).mkdir(parents=True, exist_ok=True)
    cmd = "/opt/zeek/bin/zeek -r  " \
          "{}  scripts/ssl_ext_v1.zeek  " \
          "scripts/ocsp_ext_v1.zeek scripts/http_ext_v1.zeek " \
          "LogAscii::use_json=T " \
          "SSL::disable_analyzer_after_detection=F  " \
          "LogAscii::logdir={}".format(file, dump_directory)
    execute_cmd(cmd)
    print("Ended processing {}".format(file))


def analyze_parsed_files(already_parsed_files):
    pared_ranges = set()
    for e in already_parsed_files:
        range = e.split("/")[-2]
        pared_ranges.add(range)
    return pared_ranges

files = get_leaf_files("/source/normal_log")
already_parsed_files = get_leaf_files("zeek_logs/nsec")
parsed_ranges = analyze_parsed_files(already_parsed_files)
st = time.time()
print("Total files {}".format(len(files)))
# print(mode, files)
pool = ThreadPool(50)
results = pool.map(zeekify, files)
pool.close()
pool.join()

print("Total time taken for {} files : {} minutes".format(len(files), (time.time() - st)/60))