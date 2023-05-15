import json
from collections import defaultdict
import matplotlib.pyplot as plt
from multiprocessing.dummy import Pool as ThreadPool
import pydig
import pycurl
import asyncio
import aiohttp

SAMPLE_PER_WEBSITE = 50

def box_plot(cdn_to_arr, title):
    import seaborn as sns
    sns.set()
    data_to_plot = []
    labels = []
    for cdn in cdn_to_arr:
        data_to_plot.append(cdn_to_arr[cdn])
        labels.append(cdn)

    fig = plt.figure(1, figsize=(9, 6))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

    # Create an axes instance
    ax = fig.add_subplot(111)


    bp = ax.boxplot(data_to_plot, patch_artist=True)

    ## change outline color, fill color and linewidth of the boxes
    for box in bp['boxes']:
        # change outline color
        box.set(color='#7570b3', linewidth=2)
        # change fill color
        box.set(facecolor='#1b9e77')

    ## change color and linewidth of the whiskers
    for whisker in bp['whiskers']:
        whisker.set(color='#7570b3', linewidth=2)

    ## change color and linewidth of the caps
    for cap in bp['caps']:
        cap.set(color='#7570b3', linewidth=2)

    ## change color and linewidth of the medians
    for median in bp['medians']:
        median.set(color='#b2df8a', linewidth=2)

    ## change the style of fliers and their fill
    for flier in bp['fliers']:
        flier.set(marker='o', color='#e7298a', alpha=0.5)

    ax.set_xticklabels(labels)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()

    ax.set_ylabel('millisecons')

    plt.title(title)
    plt.show()


def histogram_maker(counter, x_title, y_title, title, mul=1):
    import seaborn as sns
    sns.set()
    ans = []

    fig = plt.figure(figsize=(8, 6))
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

    for key in counter:
        ans.append((key, counter[key]))
    ans.sort()
    x_arr = [str(e[0]) for e in ans]
    y_arr = [e[1] * mul for e in ans]
    plt.bar(x_arr, y_arr, edgecolor='black')
    plt.title(title)
    plt.xlabel(x_title)
    plt.ylabel(y_title)
    plt.show()



'''
This class extracts iata from HTTP headers
'''
class CDNSigPro:
    def extract_loc(self, headers, target_cdn):
        try:
            if 'cloudflare' in target_cdn.lower():
                str = headers['CF-Ray']
                return str.split("-")[1].lower()

            if 'fastly' in target_cdn.lower():
                str = headers['X-Served-By'].split("-")[-1]
                return str

            if 'cloudfront' in target_cdn.lower():
                str = headers['X-Amz-Cf-Pop'][0: 3]
                return str

            return None

        except Exception as e:
            return None

    def analyze_tuple(self,  tuple):
        cn, target_cdn, headers, _ = tuple
        return cn, target_cdn, self.extract_loc(headers, target_cdn)

'''
These string hints are used for finding if a domain is used by a CDN
'''
CDN_hints = ['Akamai',
        'Cachefly',
        'EdgeCast',
        'Fastly',
        'Google',
        'CloudFlare',
        'Limelight',
        'Azure',
        'Limelight',
        'KeyCDN',
        'Stackpath',
        'Cloudfront'
        ]

def get_cdn_from_str(s):
    for hint in CDN_hints:
        if hint.lower() in s.lower():
            return hint

    return None


def get_cdn_to_websites(siteData):
    cdn_to_websites = defaultdict(lambda: set())

    for site in siteData:
        site_included_in_cdns = False
        try:
            for cname in siteData[site]['cnames']:
                cdnUsed = get_cdn_from_str(cname)
                if cdnUsed:
                    cdn_to_websites[cdnUsed].add(site)
                    site_included_in_cdns = True
                    break
        except:
            pass

        if not site_included_in_cdns:
            try:
                cdnUsed = get_cdn_from_str(siteData[site]['remote_owner'])
                if cdnUsed:
                    cdn_to_websites[cdnUsed].add(site)
            except:
                pass

    return cdn_to_websites

geo_hint_crawl_dump = []
async def query_through_luminati(hop, session, target):
    try:
        global geo_hint_crawl_dump

        import random, string, time
        letters = string.ascii_lowercase
        session_key = ''.join(random.choice(letters) for i in range(8)) + str(int(time.time()))

        cn = hop
        # id and passwords anonymzed
        proxy_url = 'http://lum-customer-xxx-zone-protick-dns-remote-country-{}-session-{}:xxx@zproxy.lum-superproxy.io:22225'.format(cn, session_key)

        async with session.get(url='https://{}'.format(target), proxy=proxy_url) as response:
            try:
                header_dict = dict(response.headers)
                geo_hint_crawl_dump.append((hop, target, header_dict, int(time.time())))
            except Exception as e:
                a = 1
    except Exception as e:
        a = 1
async def process_urls_async(chosen_hop_list, target):

    timeout = aiohttp.ClientTimeout(total=20)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for hop in chosen_hop_list:
            try:
                import random
                task = asyncio.ensure_future(
                    query_through_luminati(hop=hop, session=session, target=target))
                tasks.append(task)
            except Exception as e:
                pass
        execution_results = await asyncio.gather(*tasks)

'''
Rank CDNs accroding to domain count
'''
def get_rank_of_cdns(cdn_to_websites):
    cdn_arr = []
    for cdn in cdn_to_websites:
        cdn_arr.append((cdn, len(cdn_to_websites[cdn])))
    cdn_arr.sort(key=lambda x: x[1], reverse=True)
    return cdn_arr

'''
Consider only the resolution time for getting the authoritative answer
'''
def get_A_resolution_time_from_trace(trace):
    for element in trace[::-1]:
        try:
            if "A " in element:
                # milliseconds
                return int(element.split(" ")[-2])
        except:
            pass
    return None


def get_curl_timing(website):
    SAMPLE_PER_WEBSITE = 10
    curl_info_list = []

    schemed_url = website
    if "https://" not in schemed_url:
        schemed_url = "https://" + schemed_url

    for i in range(SAMPLE_PER_WEBSITE + 1):
        try:
            c = pycurl.Curl()
            c.setopt(c.URL, schemed_url)
            c.setopt(pycurl.TIMEOUT, 20)
            c.perform()
            dns_time = c.getinfo(pycurl.NAMELOOKUP_TIME)
            connect_time = c.getinfo(pycurl.CONNECT_TIME)
            app_connect_time = c.getinfo(pycurl.APPCONNECT_TIME)
            ttfb = c.getinfo(pycurl.STARTTRANSFER_TIME)
            total_time = c.getinfo(pycurl.TOTAL_TIME)
            download_speed = c.getinfo(pycurl.SPEED_DOWNLOAD)
            c.close()

            if i != 0:
                curl_info_list.append(
                    {
                        "dns_time": dns_time,
                        "connect_time": connect_time,
                        "app_connect_time": app_connect_time,
                        "ttfb": ttfb,
                        "total_time": total_time,
                        "download_speed": download_speed
                    }
                )
        except:
            pass

    print("Done with curl: {}".format(website))
    return website, curl_info_list

def get_dns_timing(website):
    SAMPLE_PER_WEBSITE = 10

    resolution_time_list = []

    resolver = pydig.Resolver(
        additional_args=[
            '+trace',
        ]
    )
    for i in range(SAMPLE_PER_WEBSITE):
        try:
            trace_result = resolver.query(website, 'A')
            a_record_resolution_time_from_trace = get_A_resolution_time_from_trace(trace_result)
            if a_record_resolution_time_from_trace:
                resolution_time_list.append(a_record_resolution_time_from_trace)
        except:
            pass

    print("Done with dns: {}".format(website))
    return website, resolution_time_list


def get_country_codes():
    import json
    f = open("data/countries.json")
    d = json.load(f)
    country_codes = []
    for e in d:
        country_codes.append(d[e]["cc"])
    return country_codes


def carry_out_exp(hops, url):
    asyncio.run(process_urls_async(chosen_hop_list=hops, target=url))


def carry_out_luminati_exp(cadidate_websites_to_cdn):
    candidate_websites = list(cadidate_websites_to_cdn.keys())

    country_codes = get_country_codes()
    for website in candidate_websites:
        carry_out_exp(hops=country_codes, url=website)

    global geo_hint_crawl_dump
    return geo_hint_crawl_dump

def get_website_to_cn_iata_pair(geo_hint_crawl_data, cadidate_websites_to_cdn):
    cdn_sig_pro = CDNSigPro()
    website_to_cn_iata_pair = defaultdict(lambda: list())
    for element in geo_hint_crawl_data:
        # geo_hint_crawl_dump.append((hop, target, header_dict, int(time.time())))
        cn, target, headers, t = element
        target_cdn = cadidate_websites_to_cdn[target]
        _, _, iata = cdn_sig_pro.analyze_tuple((cn, target_cdn, headers, t))
        website_to_cn_iata_pair[target].append((cn, iata))
    return website_to_cn_iata_pair


def get_alpha2_to_country_dict():
    import json
    f = open("data/alpha2.json")
    d = json.load(f)
    alpha2_to_country = {}
    for e in d:
        a_2_code = e['alpha-2']
        alpha2_to_country[a_2_code.lower()] = e['name'].lower()
    return alpha2_to_country

def get_iata_to_country_dict():
    import json

    iata_to_country = {}

    f = open("data/airports.json")
    d = json.load(f)
    for e in d:
        iata_to_country[e['code'].lower()] = e['country'].lower()

    return iata_to_country


def find_geohints():
    cadidate_websites_to_cdn = {
        "www.oracle.com": "Akamai",
        "www.blogger.com": "Google",
        "www.cloudflare.net": "Cloudflare",
        "www.ign.com": "Fastly",
        "www.imdb.com": "Cloudfront"
    }

    candidates_with_geo_hint = ["www.cloudflare.net", "www.ign.com", "www.imdb.com"]

    geo_hint_crawl_data = None
    geo_hint_crawl_data_Filename = 'geo_hint_crawl_data.json'
    try:
        with open(geo_hint_crawl_data_Filename, 'r') as f:
            import json
            geo_hint_crawl_data_loaded = json.load(f)
            geo_hint_crawl_data = geo_hint_crawl_data_loaded
    except Exception:
        geo_hint_crawl_data = carry_out_luminati_exp(cadidate_websites_to_cdn)
        with open(geo_hint_crawl_data_Filename, 'w') as f:
            import json
            json.dump(geo_hint_crawl_data, f)


    website_to_cn_iata_pair = get_website_to_cn_iata_pair(geo_hint_crawl_data=geo_hint_crawl_data, cadidate_websites_to_cdn=cadidate_websites_to_cdn)


    alpha2_to_country_dict = get_alpha2_to_country_dict()
    iata_to_country_dict = get_iata_to_country_dict()
    # Adjustment of missing iata
    iata_to_country_dict['qpg'] = 'Singapore'
    iata_to_country_dict['kld'] = 'Russia'
    iata_to_country_dict['par'] = 'France'
    iata_to_country_dict['pdk'] = 'United states'
    iata_to_country_dict['fty'] = 'United states'
    iata_to_country_dict['yto'] = 'China'
    cdn_to_country_iata_country_pair = defaultdict(lambda : list())

    for website in website_to_cn_iata_pair:
        if website not in candidates_with_geo_hint:
            continue

        cdn = cadidate_websites_to_cdn[website]
        total_countries = len(website_to_cn_iata_pair[website])
        iata_set = set()

        for element in website_to_cn_iata_pair[website]:
            cn, iata = element
            if iata is None:
                continue
            iata_set.add(iata)
            country_string = alpha2_to_country_dict[cn.lower()]
            iata_country = iata_to_country_dict[iata.lower()]
            cdn_to_country_iata_country_pair[website].append((country_string, iata_country))

        print(cdn, total_countries, len(iata_set))


    with open("cdn_to_country_iata_country_pair.json", 'w') as f:
        import json
        json.dump(cdn_to_country_iata_country_pair, f, indent = 2)

    return website_to_cn_iata_pair

def analyze_ping_files_from_ripe_atlas():
    cadidate_websites_to_cdn = {
        "www.oracle.com": "Akamai",
        "www.blogger.com": "Google",
        "www.roku.com": "Cloudflare",
        "www.ign.com": "Fastly",
        "www.imdb.com": "Cloudfront"
    }

    cdn_to_rtt_list = defaultdict(lambda : list())

    for key in cadidate_websites_to_cdn:
        f = open("atlas_files/{}.json".format(key))
        d = json.load(f)
        for element in d:
            average_rtt = element['avg']
            cdn_to_rtt_list[cadidate_websites_to_cdn[key]].append(average_rtt)

    return cdn_to_rtt_list

def analyze_meta_data(website_to_meta_data, cdn_to_websites):
    website_to_cdn = {}
    import statistics

    cdn_to_median_attributes = defaultdict(lambda : defaultdict(lambda : list()))

    for cdn in cdn_to_websites:
        for website in cdn_to_websites[cdn]:
            website_to_cdn[website] = cdn

    for website in website_to_meta_data:
        if website not in website_to_cdn:
            continue
        cdn = website_to_cdn[website]
        try:
            cdn_to_median_attributes[cdn]['dns'].append(statistics.median(website_to_meta_data[website]['dns']))
            cdn_to_median_attributes[cdn]['connect'].append(
                statistics.median(e['connect_time'] - e['dns_time'] for e in website_to_meta_data[website]['curl']))
            cdn_to_median_attributes[cdn]['ssl_handshake'].append(
                statistics.median(
                    e['app_connect_time'] - e['connect_time'] for e in website_to_meta_data[website]['curl']))
            cdn_to_median_attributes[cdn]['ttfb'].append(
                statistics.median(e['ttfb'] for e in website_to_meta_data[website]['curl']))
            cdn_to_median_attributes[cdn]['total'].append(
                statistics.median(e['total_time'] for e in website_to_meta_data[website]['curl']))
            cdn_to_median_attributes[cdn]['download_speed'].append(
                statistics.median(e['download_speed'] for e in website_to_meta_data[website]['curl']))
        except:
            pass

    attributes = ['dns', 'connect', 'ssl_handshake', 'ttfb', 'total', 'download_speed']

    for attribute in attributes:
        mul = 1
        if attribute != 'dns':
            mul = mul * 1000
        counter = defaultdict(lambda : 0)
        for cdn in cdn_to_median_attributes:
            if cdn == 'Azure':
                continue
            counter[cdn] = statistics.median(cdn_to_median_attributes[cdn][attribute])
        histogram_maker(counter=counter, x_title='CDNs',  y_title='median value in millisecond', title=attribute, mul=mul)


    a = 1
def analyzeSiteData(siteData):
    cdn_to_websites = get_cdn_to_websites(siteData=siteData)

    rank_of_cdns = get_rank_of_cdns(cdn_to_websites)

    websites_using_cdns = []
    for cdn in cdn_to_websites:
        websites_using_cdns += list(cdn_to_websites[cdn])

    # websites_using_cdns = websites_using_cdns

    website_to_meta_data = None
    websites_to_meta_data_Filename = 'websites_to_meta_data.json'

    try:
        with open(websites_to_meta_data_Filename, 'r') as f:
            import json
            websites_to_meta_data_Filename_loaded = json.load(f)
            website_to_meta_data = websites_to_meta_data_Filename_loaded
    except Exception:
        website_to_meta_data = defaultdict(lambda: {})
        from multiprocessing import Pool
        with Pool() as pool:
            for result in pool.imap_unordered(get_dns_timing, websites_using_cdns):
                website, resolution_time_list = result
                website_to_meta_data[website]['dns'] = resolution_time_list

        from multiprocessing import Pool
        with Pool() as pool:
            for result in pool.imap_unordered(get_curl_timing, websites_using_cdns):
                website, curl_time_list = result
                website_to_meta_data[website]['curl'] = curl_time_list

        with open(websites_to_meta_data_Filename, 'w') as f:
            import json
            json.dump(website_to_meta_data, f)

    # get geohints from http headers using brightdata proxy
    website_to_cn_iata_pair = find_geohints()
    # analyze different timing info like dns, tcp conn etc and draw bar plots
    analyze_meta_data(website_to_meta_data, cdn_to_websites)
    # get rtt list for each cdn from ripe atlas
    cdn_to_rtt_list = analyze_ping_files_from_ripe_atlas()
    box_plot(cdn_to_arr=cdn_to_rtt_list, title="RTT")

    sys.exit()

def collectSite(hostname):
    # TODO: Expand this code to collect more data!
    #
    # 1. Collect more timing information (e.g., dns resolution time).

    data = {}
    try:
        hostname_aug = hostname if hostname.startswith('www.') else 'www.'+hostname

        # Use dnspython package to obtain all CNAMEs from the hostname.
        # Many CDNs use CNAME records as a means to onboard traffic.
        import time
        import dns.resolver
        answer = dns.resolver.resolve(hostname_aug, 'A', lifetime = 5.0)
        data['cnames'] = []
        for rrset in answer.response.answer:
            for rr in rrset:
                if rr.rdtype == 1: # A
                    data['remote_ip'] = rr.address
                if rr.rdtype == 5: # CNAME
                    data['cnames'].append(str(rr.target))

        # Use Team Cymru to lookup the ASN for the remote IP based upon BGP route advertisements
        from cymruwhois import Client
        cymru = Client()
        response = cymru.lookup(data['remote_ip'])
        data['remote_asn'] = response.asn
        data['remote_owner'] = response.owner

        url = 'https://{}/'.format(hostname_aug)

        # Use urllib to download the index
        import urllib.request
        opener = urllib.request.build_opener()
        request = urllib.request.Request(url)
        start = time.time()
        resp = opener.open(request, timeout = 30)
        resp.read()
        download = time.time()
        data['download'] = download - start
        data['error'] = None
    except Exception as e:
        # Something went wrong
        data['error'] = str(e)
    return hostname, data

def collectSiteData(trancoList):
    '''
    In separate processes, fetch root object of each site, collecting timing information and IP/ASN/CNAME entries.
    '''
    print('Collecting site information...')
    siteData = {}
    from multiprocessing import Pool
    with Pool() as pool:
        from rich.progress import Progress
        with Progress() as progress:
            task = progress.add_task('[green]Sites...', total=len(trancoList))
            # Pass domains to the child processes to be fetched
            for result in pool.imap_unordered(collectSite, trancoList):
                hostname, data = result
                siteData[hostname] = data
                progress.update(task, advance=1)
    print('Complete')
    return siteData

def loadSiteData(trancoList):
    '''
    Load site data into memory.
    First try to load JSON cache file from disk if it exists.
    Fallback to collecting data if not.
    '''

    filename = 'siteData.json'
    try:
        with open(filename, 'r') as f:
            import json
            siteData = json.load(f)
            print('Loaded site data from cache on disk')
            return siteData
    except Exception:
        # Unexpected problem loading tranco list from disk.
        # It may not be downloaded yet or corrupt.
        pass

    try:
        siteData = collectSiteData(trancoList)
    except ModuleNotFoundError as e:
        # Missing a required module
        print('You are missing required package and need to install it:', e.name)
        sys.exit()
    except Exception:
        import traceback
        traceback.print_exc()
        print('An unexpected error has occurred. Please check your Internet connection and retry. If the problem persists, contact your recruiter.')
        sys.exit()
    # Write list to disk
    with open(filename, 'w') as f:
        import json
        json.dump(siteData, f, indent = 2)
    return siteData

def getTrancoList(url = 'https://tranco-list.eu/top-1m.csv.zip', n = 1000):
    '''
    Fetches the Tranco list of popular sites and parses it.
    More details at https://tranco-list.eu/
    '''
    print('Downloading Tranco list...')
    import urllib.request
    with urllib.request.urlopen(url) as f:
        content = f.read()
    import io,zipfile
    archive = zipfile.ZipFile(io.BytesIO(content))
    file = archive.read('top-1m.csv').decode('utf-8')
    import csv
    reader = csv.reader(io.StringIO(file))
    trancoList = []
    for i,pos_domain in enumerate(reader):
        if i >= n:
            break
        pos,domain = pos_domain
        trancoList.append(domain)
    print('Complete')
    return trancoList

def loadTrancoList():
    '''
    Load Tranco list into memory. First try to load JSON cache file from disk if it exists. Fallback to downloading list.
    '''
    trancoFilename = 'trancoList.json'
    try:
        with open(trancoFilename, 'r') as f:
            import json
            trancoList = json.load(f)
            print('Loaded Tranco list from cache on disk')
            return trancoList
    except Exception:
        pass

    try:
        trancoList = getTrancoList()
    except ModuleNotFoundError as e:
        # Missing a required module
        print('You are missing required package and need to install it:', e.name)
        sys.exit()
    except Exception:
        import traceback
        traceback.print_exc()
        print('An unexpected error has occurred. Please check your Internet connection and retry. If the problem persists, contact your recruiter.')
        sys.exit()
    # Write list to disk
    with open(trancoFilename, 'w') as f:
        import json
        json.dump(trancoList, f, indent = 2)
    return trancoList

if __name__ == "__main__":
    import argparse,sys
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='ThousandEyes Internet Measurement Research Internship Puzzle. This code is partially complete. Finish the code and share your insights with your recruiter.')
    args = parser.parse_args()

    # Make sure correct version of Python used.
    if (sys.version_info.major, sys.version_info.minor) < (3, 8):
        print('This code is meant to run with Python 3.8 or later.')
        sys.exit()
    # Make sure all packages needed are installed.
    try:
        import dns.resolver,cymruwhois,rich.progress
    except ModuleNotFoundError as e:
        import traceback
        traceback.print_exc()
        print('You are missing required package and need to install it:', e.name)
        print('Make sure all of the following packages are installed:')
        print('dnspython cymruwhois rich')
        sys.exit()

    trancoList = loadTrancoList()

    siteData = loadSiteData(trancoList)

    analyzeSiteData(siteData)
