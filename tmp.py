
from dns import message, query, rdatatype


q = message.make_query("alumama.7.ttlexp.exp.net-measurement.net", rdatatype.A)
a = query.udp(q, "52.44.221.99", timeout=10)

ip = str(list(a.answer[0].items.keys())[0])
ttl = a.answer[0].ttl

a = 1