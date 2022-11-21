import json
import time

import requests

# jq . anon.x509.log
# api_lst = [
#     ("ea46a68e-bca5-4857-8cde-7c4f252f80fa", "L13oziZzR3x3EHpn2R2o1uc0iObBPwRY"),
#     ("cdddad9b-f046-4e37-830e-92632e444860", "JQlt0fmoMAraVMK4WvjVJf2l535CipCA"),
#     ("fa7d8cbe-fc7e-4432-a45e-150bcb673318", "iBAj8KbK9vMExR09ALFAGxrFr84cs8id"),
#     ("9a2feeda-5795-460e-b395-285b719172b9", "NIN0BXelp08s9zJ2R3PLJUKb9TfMQcOM"),
#     ("413caf34-1844-47ec-9d59-1a7bfc66e508", "MoMXzpePGNb5QC0sYm1xZdfMzWDM4szo")
# ]

api_lst = [
    ("b71bb044-064b-4ea4-82b8-370935d2963c", "ybJCHaWEf4BzbwTo8oX4ok9WpSt8WxZV"),
    ("1b88f449-f1ab-41cb-8cf6-5d0109658296", "32QqA7zvdT0GR0Qokpe147OEBF6H427S"),
    ("84c06799-321a-434d-a2a0-385041837a24", "yMx1X7mHIUC40mUd6852ECYBnlDbIxAD"),
]



# f = open("../fingerprint_to_meta.json")
# fingerprints = json.load(f)
# a = 1
#
# left_alone = set()
# for k in fingerprints:
#     try:
#         if fingerprints[k]['error_type'] == 'quota_exceeded':
#             left_alone.add(k)
#     except:
#         pass
#
#
# with open('fingerprints_zeek_v2.json', "w") as ouf:
#     json.dump(list(left_alone), fp=ouf)



f = open("fingerprints_zeek_v2.json")
fingerprints = json.load(f)


api_index = 0
mother_bot = {}


for fingerprint in fingerprints:
    api_index = (api_index + 1) % 3
    try:
        headers = {'Content-type': 'application/json'}
        r = requests.get(
            'https://search.censys.io/api/v1/view/certificates/{}'.format(fingerprint),
            auth=(api_lst[api_index][0], api_lst[api_index][1]), headers=headers)

        mother_bot[fingerprint] = json.loads(r.content)

        print(r.status_code)
        time.sleep(1.5)
    except:
        pass


with open('fingerprint_to_meta_2.json', "w") as ouf:
    json.dump(mother_bot, fp=ouf)


