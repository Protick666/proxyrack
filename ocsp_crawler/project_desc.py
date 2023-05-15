# OCSP sizes for top 1 (??) million **
# OCSP responders for them
# Issuing certs
# Responder certs
# Delegated count **
from ocspchecker import get_ocsp_status
from multiprocessing.dummy import Pool as ThreadPool
from csv import reader
def fetch_top_websites():
    websites = []
    with open('../ocsp_crawler/data/top-1m.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        for row in csv_reader:
            websites.append(row[1])
    # return [(1, 'google.com')]
    return websites

def init(website):
    a = get_ocsp_status(website)
    a = 1

def check_ocsp():
    websites = fetch_top_websites()
    # websites = ['eclipseview.com']

    pool = ThreadPool(50)
    results = pool.map(init, websites)
    pool.close()
    pool.join()

def read_file():
    f = open("data/yo.txt")
    Lines = f.readlines()

    count = 0
    # Strips the newline character
    sizes = []
    for line in Lines:
        count += 1
        num = line.strip()
        if num == '':
            continue
        sizes.append(int(num))

    from statistics import mean

    m = mean(sizes)
    mx = max(sizes)
    p = min(sizes)
    a = 1

check_ocsp()
# read_file()




