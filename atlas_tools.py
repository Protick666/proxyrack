import json

f = open("/Users/protick.bhowmick/Downloads/20220711.json")
d = json.load(f)

asn_to_probe = {}
for e in d['objects']:
    if not e['is_public']:
        continue
    if e['id'] == 1004360:
        a = 1
    asn_to_probe[e['asn_v4']] = e['id']

f = open('dash_asns.json')
asn_dict = json.load(f)
lum_asn_set = set()
for key in asn_dict:
    lum_asn_set.update(asn_dict[key])


atlas_asn_set = set(list(asn_to_probe.keys()))

commmon_asns = list(atlas_asn_set.intersection(lum_asn_set))

f = open('done_asns.json')
done_asns = json.load(f)


commmon_asns = [e for e in commmon_asns if e not in done_asns]

import random

chosen_50 = random.sample(commmon_asns, 50)
probe_lst, probe_id_asn_tuple_list = [], []

for e in chosen_50:
    probe_lst.append(asn_to_probe[e])
    probe_id_asn_tuple_list.append((asn_to_probe[e], e))

a = ""

for e in probe_lst:
    a += "{},".format(e)
a = a[: -1]
a = a + "---"
print(a)

mother_dict = {
    "commmon_asns": commmon_asns,
    "probe_lst": probe_lst,
    "probe_id_asn_tuple_list": probe_id_asn_tuple_list
}

# [dns] udp_payload_size (integer): Set the EDNS0 option for UDP payload size to this value, between 512 and 4096.Defaults to 512)
# [dns] use_probe_resolver (boolean): Send the DNS query to the probe's local resolvers (instead of an explicitly specified target),
# [dns] set_rd_bit (boolean): Indicates Recursion Desired bit was set,
# [dns] query_class (string) = ['IN' or 'CHAOS']: The `class` part of the query used in the measurement,
# [dns] query_argument (string): The `argument` part of the query used in the measurement,
# [dns] query_type (string) = ['A' or 'AAAA' or 'ANY' or 'CNAME' or 'DNSKEY' or 'DS' or 'MX' or 'NS' or 'NSEC' or 'PTR' or 'RRSIG' or 'SOA' or 'TXT' or 'SRV' or 'NAPTR' or 'TLSA']: The `type` part of the query used in the measurement,
# [dns] ttl (boolean): Report the IP time-to-live field (hop limit for IPv6) of DNS reply packets received (only for UDP)
