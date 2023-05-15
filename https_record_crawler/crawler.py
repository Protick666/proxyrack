import asyncio
import time

import dns.asyncresolver
import dns.resolver


from csv import reader

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans

def fetch_top_websites():
    websites = []
    with open('../ocsp_crawler/data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append(row[1])
    # return [(1, 'google.com')]
    return websites

mother_dict = {}

async def crawl():
    global mother_dict
    async def resolve(domain):
        try:
            # TODO www er effect ki ??
            # if domain.startswith("www."):
            #     domain = domain[4:]

            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ['8.8.8.8']

            addr = await resolver.resolve(domain, rdtype=65)

            ans_arr = []

            for e in addr.response.answer:
                ans_arr.append(str(e))
            mother_dict[domain] = ans_arr

        except Exception as e:
            if "does not contain" in str(e):
                mother_dict[domain] = ["NP"]
            else:
                mother_dict[domain] = ["UK"]


    from pathlib import Path
    dump_directory = "https_record_dump/"
    Path(dump_directory).mkdir(parents=True, exist_ok=True)
    all_domains = fetch_top_websites()
    semi_domains = chunks(all_domains, 200)
    index = 1
    t_init = time.time()
    for chunk in semi_domains:
        await asyncio.gather(*(resolve(domain) for domain in chunk))
        print("Done {}, time {}".format(index * 200, time.time() - t_init))
        index += 1

    import json
    with open("{}/{}.json".format(dump_directory, int(time.time())), "w") as ouf:
        json.dump(mother_dict, fp=ouf)

results = asyncio.run(crawl())