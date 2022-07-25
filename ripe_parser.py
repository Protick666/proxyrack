import json

from ripe.atlas.sagan import DnsResult
#
# f = open("dns_measurement.json")
f = open("prac.json")
measurement_lst = json.load(f)

for e in measurement_lst:
    my_dns_result = DnsResult(e)
    for r in my_dns_result.responses:
        try:
            ttl = r.abuf.answers[0].ttl
            time = r.response_time
            print(ttl, time)
        except:
            pass

a = 1
