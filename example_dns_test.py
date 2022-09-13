import dns.resolver
import asyncio
import dns.asyncresolver
import socket
import time
from multiprocessing.pool import ThreadPool



l = [
    'www.pinterest.com'
]

domains = []
for _ in range(500):
    domains += l


servers = [
    '8.8.8.8',
    '8.0.7.0',
    '8.0.6.0',
    '195.99.66.220',
    '38.132.106.139',
]

#
#
# def test1(pool):
#     def resolve(domain):
#         resolver = dns.resolver.Resolver()
#         resolver.nameservers = ['8.8.8.8']
#         return (domain, resolver.resolve(domain)[0].address)
#
#     return pool.map(resolve, domains)
#
# def test2(pool):
#     def resolve(idx, domain):
#         resolver = dns.resolver.Resolver()
#         i = idx % len(servers)
#         resolver.nameservers = [servers[i]]
#         try:
#             return (domain, resolver.resolve(domain)[0].address)
#         except Exception as e:
#             print(e, servers[i])
#             return None
#
#     return pool.starmap(resolve, enumerate(domains))
#
#
# def test3(pool):
#     def resolve(domain):
#         resolver = dns.resolver.Resolver()
#         resolver.nameservers = servers[1:] # omit '8.8.8.8'
#         return (domain, resolver.resolve(domain)[0].address)
#
#     return pool.map(resolve, domains)
#
#
# def test4(pool):
#     def resolve(domain):
#         return (domain, socket.gethostbyname(domain))
#
#     return pool.map(resolve, domains)
from csv import reader

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans

def fetch_top_websites():
    websites = []
    with open('ocsp_crawler/data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append(row[1])
    # return [(1, 'google.com')]
    return websites


async def test5():
    async def resolve(domain):
        try:
            if domain.startswith("www."):
                domain = domain[4:]
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ['198.82.247.69']
            addr = await resolver.resolve(domain, rdtype=2)
            ans_list = []
            additional_lst =[]
            for e in addr.response.answer:

                ans_list.append(str(e))
            for e in addr.response.additional:
                additional_lst.append(str(e))
            return (domain, [additional_lst, ans_list])
        except Exception as e:
            a = 1

    from pathlib import Path
    dump_directory = "top_1_m_dns_v12/"
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    index = 0
    all_domains = fetch_top_websites()
    # www_domains = []

    # for domain in all_domains:
    #     if "www" not in domain:
    #         temp = "www." + domain
    #         www_domains.append(temp)
    #     else:
    #         www_domains.append(domain)

    a = 1

    semi_domains = chunks(all_domains, 200)
    index = 1
    t_init = time.time()
    for chunk in semi_domains:
        p = await asyncio.gather(*(resolve(domain) for domain in chunk))
        import json
        with open("{}/{}.json".format(dump_directory, index), "w") as ouf:
            json.dump(p, fp=ouf)
        index += 1
        print("Done {}, time {}".format(index * 200, time.time() - t_init))


# pool = ThreadPool(len(domains))

# def benchmark(fun):
#     try:
#         print()
#         print(fun.__name__)
#         start = time.time()
#         results = fun(pool)
#         print(time.time() - start)
#         print(sorted(set(results)))
#     except:
#         pass


# benchmark(test1)
# benchmark(test2)
# benchmark(test3)
# benchmark(test4)
#
# print()

results = asyncio.run(test5())