import json
import csv
from collections import defaultdict
import socks
import requests
import dnslib
import binascii
from multiprocessing import Pool, Manager

available_asn_in_proxy_rack = dict()
asn_to_info_proxy_rack = dict()

username = 'tijay'
password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'
PROXY_RACK_DNS = "premium.residential.proxyrack.net:9000"


def ip_test(tp):
    try:
        url, cn, isp = tp
        d = dnslib.DNSRecord.question("google.com")
        query_data = d.pack()
        dnsPacket = query_data

        s = socks.socksocket()
        s.settimeout(60)
        s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', 9000, True,
                    username + "-timeoutSeconds-10-country-{}-isp-{}".format(cn, isp), password)

        try:
            s.connect((url, 53))
            s.send(dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket)
        except Exception as e:
            result = str(e)
            s.close()
            print("False")
            return
        try:
            r = s.recv(1024)
            r = r.hex()
            response = binascii.unhexlify(r[4:])
            s.close()
        except:
            result = 'noResponse'
            s.close()
            print("False")
            return

        parsed_result = dnslib.DNSRecord.parse(response)
        print("True")
    except:
        print("False")
        return



def find_overlapping_asns(ttl_to_asn_dict):
    ttl_to_available_asns = defaultdict(lambda: list())
    for ttl in ttl_to_asn_dict:
        for tuple in ttl_to_asn_dict[ttl]:
            try:
                asn = tuple[1]
                asn = int(asn)
                if asn in available_asn_in_proxy_rack:
                    # ip, asn, cn, isp
                    save_tup = (tuple[0], asn, asn_to_info_proxy_rack[asn][1], asn_to_info_proxy_rack[asn][0])
                    ttl_to_available_asns[ttl].append(save_tup)
                else:
                    a = 1
            except:
                pass
    return ttl_to_available_asns


def analyze_proxy_rack_info():
    with open("isp.csv", "r") as f:
        reader = csv.reader(f, delimiter="\t")
        for i, line in enumerate(reader):
            try:
                org, cn, asn = line[0].split(",")
                if "AS" not in asn:
                    continue
                asn = asn[asn.find("AS"): asn.find(" ")][2:]
                asn = int(asn)
                available_asn_in_proxy_rack[asn] = 1
                asn_to_info_proxy_rack[asn] = (org, cn, asn)
            except:
                pass

if __name__ == '__main__':
    analyze_proxy_rack_info()
    a = 1
    f = open("dishonor_data.json")
    data = json.load(f)
    overlap = find_overlapping_asns(data['ttl_to_dishonoring_resolvers'])
    a = 1



    target_list = []
    for ttl in overlap:
        for element in overlap[ttl]:
            ip, asn, cn, isp = element
            target_list.append((ip, asn, cn, isp))
            # print(ip_test(ip, cn, isp))
    final_list = []
    for r in range(1):
        final_list = final_list + target_list
    a = 1
    with open("target_list.json", "w") as ouf:
        json.dump(final_list, fp=ouf)




    #
    # p = Pool(50)
    # result = p.map(ip_test, target_list)
    # p.close()
