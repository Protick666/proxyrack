import json
import time

import pyasn
from asn_org_tools.org_finder import AS2ISP

asndb = pyasn.pyasn('asn_org_tools/data/ipsan_db.dat')
as2isp = AS2ISP()


def get_files_from_dir(path):
        from os import listdir
        from os.path import isfile, join
        files = [path + f for f in listdir(path) if isfile(join(path, f))]
        return files


CDNS = ['Akamai',
        'Akadns',
        'Bitgravity',
        'Cachefly',
        'CDN77',
        'CDNetworks',
        'CDNify',
        'ChinaCache',
        'ChinaNetCenter',
        'EdgeCast',
        'Fastly',
        'Highwinds',
        'Internap',
        'KeyCDN',
        'google',
        'Level3',
        'Limelight',
        'MaxCDN',
        'NetDNA',
        'Telefónica',
        'XCDN',
        'CloudFlare',
        'Jetpack',
        'Rackspace',
        'CloudLayer',
        'CloudCache',
        'TinyCDN',
        'Incapsula',
        'jsDelivr',
        'EdgeCast',
        'CDNsun',
        'Limelight',
        'Azure',
        'CDNlio',
        'SoftLayer',
        'ITWorks',
        'CloudOY',
        'Octoshape',
        'Hibernia',
        'WebMobi',
        'CDNvideo',
        'zerocdn',
        "cdn",
        "alibaba",
        "netlify",
        "wixdns"
        ]

CDN_HINTS = ["Akam", "tiny", 'CDN', 'Cloudfront']

# TODO talk amazon, thirdpart

multicdns = [
        "cedexis",
        "Mlytics",
        "metacdn",
        "atanar",
]


def is_cdn(domain):
        if 'kxcdn' in domain:
                return False
        for key in CDNS + CDN_HINTS + multicdns:
                lower_key = key.lower()
                if lower_key in domain.lower():
                        return True
        return False


def get_master_list():
        import json
        master_list = []

        json_files = get_files_from_dir("top_1_m_dns_v4/")

        visited = {}

        for file in json_files:
                f = open(file)
                d = json.load(f)
                master_list = master_list + d

        for e in master_list:
                if e is None:
                        continue
                domain = e[0]
                if domain.startswith("www."):
                        domain = domain[4:]
                        visited[domain] = 1


        json_files = get_files_from_dir("top_1_m_dns/")

        for file in json_files:
                f = open(file)
                d = json.load(f)

                for e in d:
                        if e is None:
                                continue
                        domain = e[0]
                        if domain in visited:
                                continue
                        master_list.append(e)

        return master_list


def get_sld(domain):
        if domain.endswith("."):
                domain = domain[0: -1]
        parts = domain.split(".")
        return parts[-2] + "." + parts[-1]


from collections import defaultdict
culprit_set = defaultdict(lambda : 0)
culprit_set_1 = defaultdict(lambda : 0)
trans = defaultdict(lambda : 0)


def analyze_just_A(e):
        domain, records = e

        for r in records:

                all_r = r.split("\n")
                min_ttl = -1
                for e in all_r:
                        source, ttl, _, type, dest = e.split()
                        if type == 'A':
                                return dest
        return None


def analyze(e):
        domain, records = e

        init_base = get_sld(domain)
        pre = init_base
        cdn_involve = False

        # hitomi.la. 300 IN A 88.80.31.197
        # people.com.cn. 6664 IN CNAME people.com.cn.wscdns.com.

        '''
                base -> base    'same_base'
                base -> non_cdn 'base_ncdn'
                non_cdn -> cdn1 'ncdn_cdn'
                non_cdn -> non_cdn 'ncdn_ncdn'
                base -> cdn1    'base_cdn'
                cdn1 -> cdn1    'same_cdn'
                cdn1 -> cdn1    
                cdn1 -> cdn2    'diff_cdn'
                cdn2 -> IP      'end'
        '''

        event_arr = []
        cdn_ttl = -1

        for r in records:
                if 'CNAME' in r:
                        source, ttl, _, type, dest = r.split()
                        source_sld, dest_sld = get_sld(source), get_sld(dest)
                        is_source_cdn, is_dest_cdn = is_cdn(source), is_cdn(dest)

                        if source_sld != dest_sld:
                                if source_sld == init_base:
                                        if is_dest_cdn:
                                                event_arr.append(('base_cdn', int(ttl)))
                                        else:
                                                event_arr.append(('base_ncdn', int(ttl)))
                                else:
                                        if is_source_cdn or cdn_involve:
                                                if is_dest_cdn:
                                                        event_arr.append(('diff_cdn', int(ttl)))
                                                        temp_str = "{}->{}".format(source_sld, dest_sld)
                                                        trans[temp_str] += 1
                                                        if int(ttl) >= 15000:
                                                                culprit_set[source_sld] += 1
                                                                culprit_set[dest_sld] += 1
                                        elif is_dest_cdn:
                                                event_arr.append(('ncdn_cdn', int(ttl)))
                                        else:
                                                event_arr.append(('ncdn_ncdn', int(ttl)))
                        else:
                                # same
                                if source_sld == init_base:
                                        event_arr.append(('same_base', int(ttl)))
                                elif is_source_cdn or cdn_involve:
                                        event_arr.append(('same_cdn', int(ttl)))
                                        if int(ttl) >= 15000:
                                                culprit_set_1[source_sld] += 1
                                                culprit_set_1[dest_sld] += 1
                                else:
                                        event_arr.append(('ncdn_ncdn', int(ttl)))

                        if is_source_cdn or is_dest_cdn:
                                cdn_involve = True


                elif "A" in r:
                        all_r = r.split("\n")
                        min_ttl = -1
                        for e in all_r:
                                source, ttl, _, type, dest = e.split()
                                if min_ttl == -1:
                                        min_ttl = int(ttl)
                                else:
                                        min_ttl = min(min_ttl, int(ttl))
                        event_arr.append(('end', min_ttl))
                        cdn_ttl = min_ttl

        return ((cdn_involve), event_arr, cdn_ttl)


def make_master_list():
        master_list = get_master_list()
        a = 1
        import json
        with open("master_list.json", "w") as ouf:
                json.dump(master_list, fp=ouf, indent=2)


def get_a():
        f = open("master_list.json")
        d = json.load(f)
        mother_dict = {}

        for e in d:
                if e is None:
                        continue

                p = analyze_just_A(e)
                key = e[0]
                if key.startswith("www."):
                        key = key[4:]
                if p is not None:
                        mother_dict[key] = p
        return mother_dict


def analyze_init():
        f = open("master_list.json")
        d = json.load(f)

        viss = {}
        mother_dict = {}
        for e in d:
                if e is None:
                        continue

                p = analyze(e)
                a = 1
                # 21600, 3600
                yo = p[0]
                if int(p[2]) == 21600 and p[0]:
                        yo = False
                mother_dict[e[0]] = {
                        "cdn": p[0],
                        "events": p[1]
                }
                # if len(e[1]) > 1 and p[0] is False:
                #         for t in e[1]:
                #                 #
                #                 is_p = False
                #                 if 'CNAME' in t:
                #                         source, ttl, _, type, dest = t.split()
                #                         temp = get_sld(dest)
                #                         temp1 = get_sld(source)
                #                         if temp not in viss and temp != temp1:
                #                                 if not is_p:
                #                                         print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                #                                         print(e[0])
                #                                         is_p = True
                #                                 print(temp)
                #                                 viss[temp] = 1

        arr =[]
        for key in trans:
                arr.append((trans[key], key))
        arr.sort(reverse=True)
        a = 1

        with open("mother_dict.json", "w") as ouf:
                json.dump(mother_dict, fp=ouf, indent=2)


def find_ttl(events, str):
        if str == "mid":
                min_ttl = -1
                for e in events:
                        if e[0] in ['diff_cdn']:
                                if min_ttl == -1:
                                        min_ttl = e[1]
                                else:
                                        min_ttl = min(min_ttl, e[1])
                return min_ttl

        else:
                for e in events:
                        if e[0] == str:
                                return e[1]


def prep_graph():
        '''
                        base -> base    'same_base'
                        base -> non_cdn 'base_ncdn'
                        non_cdn -> cdn1 'ncdn_cdn'
                        non_cdn -> non_cdn 'ncdn_ncdn'
                        base -> cdn1    'base_cdn'
                        cdn1 -> cdn1    'same_cdn'
                        cdn1 -> cdn1
                        cdn1 -> cdn2    'diff_cdn'
                        cdn2 -> IP      'end'
        '''
        f = open("mother_dict.json")
        d = json.load(f)

        no_cdn_a = []
        cdn_a = []
        cdn_mid = []

        for domain in d:
                is_cdn_involved, events = d[domain]['cdn'],  d[domain]['events']
                if not is_cdn_involved:
                        ttl = find_ttl(events, 'end')
                        no_cdn_a.append(ttl)
                else:
                        ttl = find_ttl(events, 'end')
                        cdn_a.append(ttl)

                        ttl = find_ttl(events, 'mid')
                        cdn_mid.append(ttl)

        ttl_dict = {
                "no_cdn_a": no_cdn_a,
                "cdn_a": cdn_a,
                "cdn_mid": cdn_mid
        }
        # 21600, 3600
        a = 1

        with open("mother_ttl_dict.json", "w") as ouf:
                json.dump(ttl_dict, fp=ouf, indent=2)


c_name_domain_set = set()
c_name_count = 0
ns_count = 0


only_cname_ttl = []
all_other_ttl = []

def prep_graph_v2():
        global c_name_count
        global ns_count
        f = open("ns_org_list.json")
        mo_tuple = json.load(f)

        domain_to_ns_org_a_org = {}
        for e in mo_tuple:
                domain_to_ns_org_a_org[e[0]] = (e[1], e[2])

        '''
                        base -> base    'same_base'
                        base -> non_cdn 'base_ncdn'
                        non_cdn -> cdn1 'ncdn_cdn'
                        non_cdn -> non_cdn 'ncdn_ncdn'
                        base -> cdn1    'base_cdn'
                        cdn1 -> cdn1    'same_cdn'
                        cdn1 -> cdn1
                        cdn1 -> cdn2    'diff_cdn'
                        cdn2 -> IP      'end'
        '''
        f = open("mother_dict.json")
        d = json.load(f)

        no_cdn_a = []
        cdn_a = []
        cdn_mid = []

        aaa = []

        for domain in d:
                key = domain
                if key.startswith("www."):
                        key = key[4:]

                is_cdn_involved, events = d[domain]['cdn'],  d[domain]['events']
                if not is_cdn_involved:

                        ttl = find_ttl(events, 'end')
                        all_other_ttl.append(ttl)

                        if key in domain_to_ns_org_a_org:
                                ns_org, a_org = domain_to_ns_org_a_org[key]
                                if is_cdn(ns_org) and is_cdn(a_org):
                                        cdn_a.append(ttl)
                                        ns_count += 1
                                        if ttl == 21600:
                                                aaa.append((domain, ns_org, a_org))
                                        continue
                        no_cdn_a.append(ttl)
                else:

                        c_name_count += 1
                        c_name_domain_set.add(domain)
                        ttl = find_ttl(events, 'end')
                        only_cname_ttl.append(ttl)
                        cdn_a.append(ttl)

                        # ttl = find_ttl(events, 'mid')
                        # cdn_mid.append(ttl)

        ttl_dict = {
                "no_cdn_a": no_cdn_a,
                "cdn_a": cdn_a,
        }
        # 21600, 3600
        a = 1

        new_stuff = {
                "cname_ttl": only_cname_ttl,
                "other_ttl": all_other_ttl
        }

        with open("mother_ttl_dict.json", "w") as ouf:
                json.dump(ttl_dict, fp=ouf)

        with open("mother_ttl_dict_reload.json", "w") as ouf:
                json.dump(new_stuff, fp=ouf)

        with open("lst_to_seee.json", "w") as ouf:
                json.dump(aaa, fp=ouf)

        with open("cname_domain_list.json", "w") as ouf:
                json.dump(list(c_name_domain_set), fp=ouf)

        print("Cname: ", c_name_count, "NS: ", ns_count, "total: ", ns_count + c_name_count)



asn_to_org = {}

def get_org(ip):
        asn = asndb.lookup(ip)[0]

        if asn in asn_to_org:
                return asn_to_org[asn]


        org = str(as2isp.getISP("20221212", asn)[0])
        asn_to_org[asn] = org
        return org


def proc_e(e, domain_to_a):
        domain = e[0]

        key = domain
        if key.startswith("www."):
                key = key[4:]

        # list
        ns_a_records = e[1][0]

        ns_records = e[1][1][0].split('\n')

        ns = []
        for p in ns_records:
                try:
                        source, ttl, _, type, dest = p.split()
                        if type == "NS":
                                ns.append(dest)
                except Exception as e:
                        a = 1

        for p in ns_a_records:
                source, ttl, _, type, dest = p.split()
                if type == "A" and source in ns:
                        org = get_org(dest)
                        ac_ip = domain_to_a[key]
                        ip_org = get_org(ac_ip)
                        # second ta bepar
                        return (key, org, ip_org)

        return None


def get_ns_records():
        domain_to_a = get_a()
        a = 1
        base_dir = "top_1_m_dns_v12/"
        files = get_files_from_dir(base_dir)
        ans_list = []
        tot_file = len(files)
        index = 0
        init_time = time.time()

        for f in files:
                index += 1
                ff = open(f)
                d = json.load(ff)

                for e in d:
                        try:
                                tuple = proc_e(e, domain_to_a)
                                if tuple is not None:
                                        ans_list.append(tuple)
                        except:
                                pass
                a = 1
                print("Done {}/{}, time:{}".format(index, tot_file, (time.time() - init_time)))

        with open("ns_org_list.json", "w") as ouf:
                json.dump(ans_list, fp=ouf, indent=2)












# make_master_list()
# analyze_init()
# a = 1
analyze_init()
prep_graph_v2()
# get_ns_records()


a = 1
# for e in d:
#         try:
#                 print(e[0])
#                 for t in e[1]:
#                         print(t)
#                 print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
#         except:
#                 pass



def asn_tester():
        a = 1


# asn_tester()









