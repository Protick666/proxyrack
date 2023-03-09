import time

import certstream
import redis

LOCAL = False

LOCAL_REDIS_HOST = "pharah.cs.vt.edu"
REMOTE_REDIS_HOST = "pharah-db.cs.vt.edu"



if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

r = redis.Redis(host=redis_host, port=6379, db=4,
                password="certificatesarealwaysmisissued")

def get_ocsp_url(info_access):
    segments = info_access.split("\n")
    for segment in segments:
        if segment.startswith("OCSP"):
            nested = segment.split(" ")
            for e in nested:

                if e.startswith("URI"):
                    print(e)
                    url = e[4: ]
                    return url
    return None

goog_set = set()
# goog_dict = {}

def print_callback(message, context):
    global goog_set

    try:
        if message['message_type'] == "heartbeat":
            return

        if message['message_type'] == "certificate_update":
            finger_print_ori = message['data']['leaf_cert']['fingerprint']
            akid_ori = message['data']['leaf_cert']['extensions']['authorityKeyIdentifier']

            if akid_ori.startswith("keyid:"):
                akid_ori = akid_ori[len("keyid:"):]

            akid_ori = akid_ori.strip()
            akid = akid_ori.replace(":", "")
            finger_print = finger_print_ori.replace(":", "")
            serial = message['data']['leaf_cert']['serial_number']
            info_access = message['data']['leaf_cert']['extensions']['authorityInfoAccess']

            ocsp_url = get_ocsp_url(info_access)

            if 'pki.goog' in ocsp_url:
                if len(goog_set) >= 3 and ocsp_url not in goog_set:
                    return
                else:
                    goog_set.add(ocsp_url)

            # has to be set
            r.sadd("ocsp_urls", ocsp_url)
            # r.lpush("ocsp_urls", ocsp_url)

            epoch = int(time.time())
            day_index = (epoch // (24 * 60 * 60)) % 2
            serial_key = "{}-{}".format(day_index, ocsp_url)
            r.lpush(serial_key, "{}:{}:{}".format(serial, finger_print, akid))
            r.ltrim(serial_key, 0, 999)

            '''
                ocsp_url_set 
                ocsp_url_to_serial_stuff
                akid_to_cert
            '''

            # sys.stdout.flush()
    except:
        pass

# logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')

'''
    AKID CAPS LOCK
'''
def transfer_akids():
    parent_r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")
    child_r = redis.Redis(host=redis_host, port=6379, db=4,
                password="certificatesarealwaysmisissued")

    # ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
    all_keys = parent_r.keys("*ocsp:akid*")
    for key in all_keys:
        key_decoded = key.decode()
        parent_value = parent_r.get(key).decode()
        print(key_decoded, parent_value)
        child_r.set(key_decoded, parent_value)

# transfer_akids()