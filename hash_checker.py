import json
import hashlib

ext_set = set()
for line in open('anon.ocsp_ext_v1.log', 'r'):
    cls = json.loads(line)
    ext_set.add(cls['serialNumberHash'])


# ocsp_set = set()
# for line in open('anon.ocsp.log', 'r'):
#     cls = json.loads(line)
#     ocsp_set.add(cls['serialNumberSHA1'])

# fset_lower = set()
# fset_upper = set()
serials_unhashed = set()
for line in open('anon.x509.log', 'r'):
    cls = json.loads(line)
    serials_unhashed.add(cls['certificate_serial'])

# for serial in serials_unhashed:
#     serial_upper = serial.upper()
#     serial_lower = serial.lower()
#     myhash_upper = hashlib.sha1(serial_upper.encode('utf-8'))
#     myhash_lower = hashlib.sha1(serial_lower.encode('utf-8'))
#     fset_lower.add(myhash_lower.hexdigest())
#     fset_upper.add(myhash_upper.hexdigest())

# set_1 = ext_set.union(ocsp_set)
# set_2 = fset_lower.union(fset_upper)
print(len(serials_unhashed))
print(len(ext_set))
print(len(serials_unhashed.intersection(ext_set)))
print(list(serials_unhashed.intersection(ext_set))[0])



