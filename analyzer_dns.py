import json

import pyasn

from asn_org_tools.org_finder import AS2ISP

asndb = pyasn.pyasn('asn_org_tools/data/ipsan_db.dat')
as2isp = AS2ISP()

ip_to_asn = {}
asn_to_org = {}

def get_asn(ip):
    if ip in ip_to_asn:
        return ip_to_asn[ip]
    asn = asndb.lookup(ip)[0]
    ip_to_asn[ip] = asn
    return asn


def get_org(asn):
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
        asn = get_asn(ip)
        org = get_org(asn)
        ip_to_org[ip] = org
        return org
    except:
        return "Void"

data_path = '/home/protick/logs.data-10-21-13-20-49-1666358449'

orig_ips = []


def is_vtech(ip):
    org = get_org_from_ip(ip)
    return 'Virginia Polytechnic' in org



def load_data():
    data = []
    count = 0
    print("Kiii")
    with open(data_path + '/anon.dns.log') as f:
        for line in f:
            data.append(json.loads(line))
    print("Ziii")

    for record in data:
        try:
            rtt = False
            if 'rtt' in record:
                rtt = True
            orig_ips.append((record['id_orig_h'], rtt, is_vtech(record['id_orig_h'])))
        except:
            continue

    inside_query = 0
    inside_query_rtt = 0
    for e in orig_ips:
        if e[2]:
            inside_query += 1
            if e[1]:
                inside_query_rtt += 1

    print(len(orig_ips), inside_query, inside_query_rtt)

# print(is_vtech('20.189.173.2'))

