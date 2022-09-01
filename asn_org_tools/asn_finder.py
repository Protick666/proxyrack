import json

import pyasn

asndb = pyasn.pyasn('data/ipsan_db.dat')



def get_asn(ip):
    # TODO what returns for not present??
    try:
        asn = asndb.lookup(ip)[0]
        if type(asn) != type(1):
            return None
        return asn
    except:
        return None




