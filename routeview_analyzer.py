from multiprocessing.dummy import Pool as ThreadPool
import pyasn
cdn = 'facebook'

from asn_org_tools.org_finder import AS2ISP

asndb = pyasn.pyasn('asn_org_tools/data/ipsan_db.dat')
as2isp = AS2ISP()

ip_to_asn = {}
asn_to_org = {}

def get_korea_asns():
    file1 = open('bgppath/korea', 'r')
    Lines = file1.readlines()
    asn_list = []
    for line in Lines:
        segments = line.split()
        asn = segments[0]
        asn_list.append(asn[2:])
    asn_list = [int(e) for e in asn_list]
    return asn_list

korea_asns = set(get_korea_asns())

def get_ip_to_asn(ip):
    if ip in ip_to_asn:
        return ip_to_asn[ip]
    asn = asndb.lookup(ip)[0]
    ip_to_asn[ip] = asn
    return asn


def get_asn_to_org(asn):
    if asn in asn_to_org:
        return asn_to_org[asn]
    org, cn = str(as2isp.getISP("20221212", asn)[0]), str(as2isp.getISP("20221212", asn)[1])
    asn_to_org[asn] = org
    return org

ip_to_org = {}

def get_org_from_ip(ip):
    try:
        if ip in ip_to_org:
            return ip_to_org[ip]
        asn = get_ip_to_asn(ip)
        org = get_asn_to_org(asn)
        ip_to_org[ip] = org
        return org
    except:
        return "Void"


def get_ip_to_org_cn(ip):
    org = get_org_from_ip(ip)
    return org, None

def is_korean(asn):
    return asn in korea_asns

def has_korean(as_path):
    for asn in as_path:
        if  asn in korea_asns:
            return True
    return False


from collections import defaultdict

prefix_cdn_asn_isp = defaultdict(lambda : list())
prefix_cdn_asn_cdn = defaultdict(lambda : list())
prefix_isp_asn_cdn = defaultdict(lambda : list())

def shortify(org):
    org = org.strip()
    segments = org.split()
    if segments > 2:
        return "{} {}".format(segments[0], segments[1])
    else:
        return org


def make_line(prefix, as_path, prefix_owner_org, date_str):
    print("go")
    s = ""
    print(prefix, as_path, prefix_owner_org, date_str)
    for asn in as_path:
        if is_korean(asn):
            appendix = "KR"
        else:
            appendix = "Non-KR"

        s = s + "({}-{}-{})->".format(asn, shortify(get_asn_to_org(asn)), appendix)

    s = s[: -2]
    s = "({}-{}):::{}".format(prefix, prefix_owner_org, s)
    print(s)
    return date_str, s



def find_case(line, date_str):
    # prefix_cdn_asn_isp = defaultdict(lambda: list()) -> 1, 2
    # prefix_cdn_asn_cdn = defaultdict(lambda: list()) -> 3, 4
    # prefix_isp_asn_cdn = defaultdict(lambda: list()) -> 5, 6
    # 7 -> unknown

    try:
        prefix = line.split("|")[-3].split("/")[0]
        as_path = line.split("|")[-2].split(" ")
        as_path = [int(e) for e in as_path]
        last_as = as_path[-1]
        prefix_asn = get_ip_to_asn(prefix)
        prefix_owner_org, _ = get_ip_to_org_cn(prefix)
        last_as_owner_org = get_asn_to_org(last_as)

        if is_korean(last_as):
            a = 1
        a = 1
        if cdn.lower() in prefix_owner_org.lower():
            if is_korean(last_as):
                prefix_cdn_asn_isp[0].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
            elif cdn.lower() in last_as_owner_org.lower():
                last_second_as = as_path[-2]
                if is_korean(last_second_as):
                    prefix_cdn_asn_cdn[0].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
                elif has_korean(as_path):
                    prefix_cdn_asn_cdn[1].append((make_line(prefix, as_path, prefix_owner_org, date_str)))

                # prefix_cdn_asn_isp[0].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
            elif has_korean(as_path):
                prefix_cdn_asn_isp[1].append((make_line(prefix, as_path, prefix_owner_org, date_str)))

        elif is_korean(prefix_asn) and cdn.lower() in last_as_owner_org.lower():
            last_second_as = as_path[-2]
            if is_korean(last_second_as):
                prefix_isp_asn_cdn[0].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
            else:
                prefix_isp_asn_cdn[1].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
        else:
            a = 1
    except Exception as e:
        a = 1

def get_chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans

def analyze_line_chunk(chunk):
    for line_ in chunk:
        try:
            # prefix_cdn_asn_isp = defaultdict(lambda: list()) -> 1, 2
            # prefix_cdn_asn_cdn = defaultdict(lambda: list()) -> 3, 4
            # prefix_isp_asn_cdn = defaultdict(lambda: list()) -> 5, 6
            # 7 -> unknown

            line = line_.strip()

            case = find_case(line, '20230310')


        except Exception as e:
            a = 1

def analyze_file(filename):
    date_str = filename.split("/")[-1]
    file = open(filename, 'r')
    lines = file.readlines()
    tot_lines = len(lines)
    index = 0

    chunks = get_chunks(lines, 200)

    pool = ThreadPool(50)
    results = pool.map(analyze_line_chunk, chunks)
    pool.close()
    pool.join()



def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files


files = get_files_from_dir("/net/data/rpki/raw-datasets/routeviews/bgpdump-parsed-reduced/bgpdata/")
filtered_files = []
allowed_strs = ['202302']
for file in files:
    for s in allowed_strs:
        if s in file:
            filtered_files.append(file)

index = 1
for file in filtered_files:
    analyze_file( file)
    print("Done with {}/{}".format(index,len(filtered_files)))
    index += 1

# prefix_cdn_asn_isp = defaultdict(lambda : list())
# prefix_cdn_asn_cdn = defaultdict(lambda : list())
# prefix_isp_asn_cdn = defaultdict(lambda : list())

d = {
    "prefix_cdn_asn_isp": prefix_cdn_asn_isp,
    "prefix_cdn_asn_cdn": prefix_cdn_asn_cdn,
    "prefix_isp_asn_cdn": prefix_isp_asn_cdn
}

import json
with open("asns.json", "w") as ouf:
    json.dump(d, fp=ouf)