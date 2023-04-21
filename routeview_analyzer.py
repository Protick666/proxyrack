from multiprocessing.dummy import Pool as ThreadPool
import pyasn
cdn = None
#
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

prefix_cdn_asn_isp_global = defaultdict(lambda : list())
prefix_cdn_asn_cdn_global = defaultdict(lambda : list())
prefix_isp_asn_cdn_global = defaultdict(lambda : list())

def shortify(org):
    org = org.strip()
    segments = org.split()
    if len(segments) > 2:
        return "{} {}".format(segments[0], segments[1])
    else:
        return org


def make_line(prefix, as_path, prefix_owner_org, date_str, vantage):
    try:
        # print("go")
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
        return date_str, vantage, s
    except Exception as e:
        print(e)



def find_case(line, date_str, vantage, prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn):
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
                prefix_cdn_asn_isp[0].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))
            elif cdn.lower() in last_as_owner_org.lower():
                last_second_as = as_path[-2]
                if is_korean(last_second_as):
                    prefix_cdn_asn_cdn[0].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))
                elif has_korean(as_path):
                    prefix_cdn_asn_cdn[1].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))

                # prefix_cdn_asn_isp[0].append((make_line(prefix, as_path, prefix_owner_org, date_str)))
            elif has_korean(as_path):
                prefix_cdn_asn_isp[1].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))

        elif is_korean(prefix_asn) and cdn.lower() in last_as_owner_org.lower():
            last_second_as = as_path[-2]
            if is_korean(last_second_as):
                prefix_isp_asn_cdn[0].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))
            else:
                prefix_isp_asn_cdn[1].append((make_line(prefix, as_path, prefix_owner_org, date_str, vantage)))
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

def analyze_line_chunk(tup):
    prefix_cdn_asn_isp = defaultdict(lambda: list())
    prefix_cdn_asn_cdn = defaultdict(lambda: list())
    prefix_isp_asn_cdn = defaultdict(lambda: list())


    chunk, date_str, vantage = tup
    for line_ in chunk:
        try:
            # prefix_cdn_asn_isp = defaultdict(lambda: list()) -> 1, 2
            # prefix_cdn_asn_cdn = defaultdict(lambda: list()) -> 3, 4
            # prefix_isp_asn_cdn = defaultdict(lambda: list()) -> 5, 6
            # 7 -> unknown

            line = line_.strip()
            case = find_case(line, date_str, vantage, prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn)


        except Exception as e:
            a = 1

    return prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn

def analyze_file(filename):
    global prefix_cdn_asn_isp_global, prefix_cdn_asn_cdn_global, prefix_isp_asn_cdn_global
    date_str = filename.split("/")[-1]
    vantage = filename.split("/")[-2]
    file = open(filename, 'r')
    lines = file.readlines()
    tot_lines = len(lines)
    index = 0

    chunks = get_chunks(lines, 300)
    chunk_date_tuple_list = []
    for chunk in chunks:
        chunk_date_tuple_list.append((chunk, date_str, vantage))

    from multiprocessing import Pool
    with Pool() as pool:
        for result in pool.imap_unordered(analyze_line_chunk, chunk_date_tuple_list):
            prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn = result

            prefix_cdn_asn_isp_global[0] = prefix_cdn_asn_isp_global[0] + prefix_cdn_asn_isp[0]
            prefix_cdn_asn_isp_global[1] = prefix_cdn_asn_isp_global[1] + prefix_cdn_asn_isp[1]

            prefix_cdn_asn_cdn_global[0] = prefix_cdn_asn_cdn_global[0] + prefix_cdn_asn_cdn[0]
            prefix_cdn_asn_cdn_global[1] = prefix_cdn_asn_cdn_global[1] + prefix_cdn_asn_cdn[1]

            prefix_isp_asn_cdn_global[0] = prefix_isp_asn_cdn_global[0] + prefix_isp_asn_cdn[0]
            prefix_isp_asn_cdn_global[1] = prefix_isp_asn_cdn_global[1] + prefix_isp_asn_cdn[1]

    # pool = ThreadPool(100)
    # prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn = pool.map(analyze_line_chunk, chunk_date_tuple_list)
    # pool.close()
    # pool.join()



def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files

# import json
# f = open("bgppath/data/fb-asns.json")
# d = json.load(f)
# a = 1

dirs = ['bgpdata',
'route-views.chile',
'route-views.mwix',
'route-views.sg',
'route-views.eqix',
'route-views.napafrica',
'route-views.soxrs',
'route-views2.saopaulo',
'route-views.flix',
'route-views.nwax',
'route-views.sydney',
'route-views3',
'route-views.isc',
'route-views.perth',
'route-views.telxatl',
'route-views4',
'route-views.jinx',
'route-views.saopaulo',
'route-views.wide',
'route-views6',
'route-views.kixp',
'route-views.chicago',
'route-views.linx',
'route-views.sfmix']

def init(n):
    global cdn
    cdn = n
    files = []
    for dir in dirs:
        # TODO change
        for year in range(2013, 2024):
            for month in range(1, 13):
                month_str = str(month)
                if month < 10:
                    month_str = "0" + month_str
                for date in ["01", "08", "15", "22"]:
                    files.append(
                        "/net/data/rpki/raw-datasets/routeviews/bgpdump-parsed-reduced/{}/{}{}{}".format(dir, year,
                                                                                                         month_str, date))


    index = 1
    print("Total files to analyze {}".format(len(files)))

    for file in files:
        try:
            analyze_file(file)
        except:
            pass
        print("Done with {}/{}".format(index, len(files)))
        index += 1

    d = {
        "prefix_cdn_asn_isp": prefix_cdn_asn_isp_global,
        "prefix_cdn_asn_cdn": prefix_cdn_asn_cdn_global,
        "prefix_isp_asn_cdn": prefix_isp_asn_cdn_global
    }

    import json
    with open("routeviews-{}-v2.json".format(cdn), "w") as ouf:
        json.dump(d, fp=ouf)


init("facebook")