import json
from collections import defaultdict
from multiprocessing.dummy import Pool as ThreadPool

base_path = '/home/protick/zeek_final/anon/anon.'

import csv

class Config_DNS:
    total_dns_conn = 0
    distinct_domains = set()
    distinct_source = set()
    distinct_dest = set()

    def print(self):
        print("************** DNS stats ***************")
        print("{} : {}".format('total_dns_conn', self.total_dns_conn))
        print("{} : {}".format('distinct_domains', len(self.distinct_domains)))
        print("{} : {}".format('distinct_source', len(self.distinct_source)))
        print("{} : {}".format('distinct_dest', len(self.distinct_dest)))
        print("**************************************")


class Config_TLS:
    total_tls_conn = 0
    total_tls_1_2 = 0
    distinct_domains = set()
    distinct_source = set()
    distinct_dest = set()
    distinct_cert_fp = set()
    distinct_signer_cert_fp = set()

    def print(self, dns_config: Config_DNS):
        print("************** TLS stats ***************")
        print("{} : {}".format('total_tls_conn', self.total_tls_conn))
        print("{} : {}".format('total_tls_1_2', self.total_tls_1_2))
        print("{} : {}".format('distinct_domains', len(self.distinct_domains)))
        print("{} : {}".format('distinct_source', len(self.distinct_source)))
        print("{} : {}".format('distinct_dest', len(self.distinct_dest)))
        print("{} : {}".format('distinct_cert_fp', len(self.distinct_cert_fp)))
        print("{} : {}".format('distinct_signer_cert_fp', len(self.distinct_signer_cert_fp)))
        print("{} : {}".format('domains_over_lapped_with_dns', len(self.distinct_domains.intersection(dns_config.distinct_domains))))
        print("**************************************")


config_tls = Config_TLS()
config_dns = Config_DNS()

def get_chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


def analyze_dns_chunk(chunk):
    for e in chunk:
        config_dns.distinct_domains.add(e['query'])
        config_dns.distinct_source.add(e['id_orig_h'])

def get_final_list():
    class Meta:
        pass




    ssl_log = []
    for line in open('{}ssl.log'.format(base_path), 'r'):
        ssl_log.append(json.loads(line))

    config_tls.total_tls_conn = len(ssl_log)

    tls_2 = []

    for e in ssl_log:
        try:
            if e['version'] == 'TLSv12':
                config_tls.total_tls_1_2 += 1
                config_tls.distinct_domains.add(e['server_name'])
                config_tls.distinct_source.add(e['id_orig_h'])
                config_tls.distinct_dest.add(e['id_resp_h'])
                config_tls.distinct_cert_fp.add(e['cert_chain_fps'][0])
                config_tls.distinct_signer_cert_fp.add(e['cert_chain_fps'][1])
                # timestamp	source     dest     domain_name            fp      signer_fp
                signer_cert_fingerprints = ""
                for i in range(1, len(e['cert_chain_fps'])):
                    signer_cert_fingerprints = str(e['cert_chain_fps'][i]) + "+"
                    if i == len(e['cert_chain_fps']) - 1:
                        signer_cert_fingerprints = signer_cert_fingerprints[0: -1]

                tls_2.append((e['ts'], e['id_orig_h'], e['id_resp_h'], e['server_name'], e['cert_chain_fps'][0], signer_cert_fingerprints))
        except Exception as e:
            print(e)
            pass

    dns_log = []
    for line in open('{}dns.log'.format(base_path), 'r'):
        dns_log.append(json.loads(line))

    config_dns.total_dns_conn = len(dns_log)
    dns_chunks = get_chunks(dns_log, 5000)

    pool = ThreadPool(50)
    results = pool.map(analyze_dns_chunk, dns_chunks)
    pool.close()
    pool.join()



    import csv

    # field names
    fields = ['timestamp', 'source', 'dest', 'domain_name_from_sni', 'leaf_cert_fingerprint', 'signer_cert_fingerprints']

    # data rows of csv file

    with open('tls_12.csv', 'w') as f:
        # using csv.writer method from CSV package
        write = csv.writer(f)
        write.writerow(fields)
        write.writerows(tls_2)


    config_tls.print()
    config_dns.print()


