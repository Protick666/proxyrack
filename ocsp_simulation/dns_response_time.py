import dns.resolver
import time

def resolve_domains(domain_resolver_tuple):
    try:
        domain, resolver_ip = domain_resolver_tuple

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        answers = resolver.resolve(domain)

        return answers.response.time, domain, resolver_ip
    except Exception as e:
        print("xxx")
        return -1, 'x', 'x'

def parse_dns(dir):
    base_path = dir + "/"

    ans = []

    dns_log = []
    for line in open('{}dns.log'.format(base_path), 'r'):
        dns_log.append(json.loads(line))

    for e in dns_log:
        try:
            ans.append(e['query'])
        except:
            pass

    return ans

def get_qnames_from_nsec_exp():
    def get_dirs(path):
        import os
        return [os.path.join(path, name) for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]

    directories = get_dirs("/net/data/dns-ttl/pcap/zeek_logs/nsec")

    ans = []

    with Pool() as pool:
        for res in pool.imap_unordered(parse_dns, directories):
            try:
                ans = ans + res
            except:
                pass

    ans = list(set(ans))

    return ans


def load_qnames():
    import json

    filename = 'data/q_names.json'

    try:
        with open(filename, 'r') as f:
            import json
            q_names = json.load(f)
            return q_names
    except Exception:
        pass

    q_names = get_qnames_from_nsec_exp()

    with open("data/q_names.json", "w") as ouf:
        json.dump(q_names, fp=ouf)

    return q_names




if __name__ == '__main__':

    qnames = load_qnames()

    from multiprocessing import Pool

    qname_tuples = []

    for resolver_ in ['8.8.8.8', '1.1.1.1']:
        for qname in qnames:
            # domain, resolver = domain_resolver_tuple
            qname_tuples.append((qname, resolver_))

    qname_resolver_to_response_time = {}

    with Pool() as pool:
        for result in pool.imap_unordered(resolve_domains, qname_tuples):
            res_time, domain, resolv = result
            qname_resolver_to_response_time["{}:{}".format(domain, resolv)] = res_time

            # print(lst)
            # print("xxx", prefix_cdn_asn_isp, prefix_cdn_asn_cdn, prefix_isp_asn_cdn)

    import json
    with open("data/qname_resolver_to_response_time.json", "w") as ouf:
        json.dump(qname_resolver_to_response_time, fp=ouf)