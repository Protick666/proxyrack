import sys

sys.path.insert(0, 'lib')
from sql import *
from cert_cnt import *
from top_cert import *
from validity import *

import gevent.monkey
import random

gevent.monkey.patch_all()
from gevent.pool import Pool

import inspect
import time
import re
import os
import base64
import select
import socket
import operator
import ssl
import random
import requests

port = 443
POOL_SIZE = 100
zproxy_ips = getSPList()
session_list = {}


def isDuplicateCID(ccode, session, zproxy_ip, zproxy_id):
    url = "http://ec2-52-70-160-126.compute-1.amazonaws.com/1"
    auth = 'lum-customer-mmlab-zone-expcert-dns-remote-country-%s-session-%s:ea3099501e1b' % \
           (ccode, session)

    try:
        r = requests.get(url, timeout=10, verify=False,
                         proxies={'http': 'http://' + auth + '@%s:22225' % zproxy_ip},
                         headers={
                             'Proxy-Authorization': 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')})

        header = r.raw._original_response.getheaders()
        cid = re.findall(r"cp[0-9]+", str(header))[-1]
        return (cid in cid_set)
    except:
        return False  ## conservative approach


def getCertificate(url, port, ccode, session, zproxy_ip, zproxy_id, retry_num):
    global cid_set

    CONNECT = "CONNECT %s:%s HTTP/1.0\r\n" % (url, port)
    auth = 'lum-customer-mmlab-zone-expcert-dns-remote-country-%s-session-%s:ea3099501e1b' % \
           (ccode, session)

    headers = {}
    headers['Proxy-Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('utf-8')
    headers['Connection'] = 'Close'
    CONNECT += '\r\n'.join('%s: %s' % (k, v) for (k, v) in headers.items()) + '\r\n\r\n'

    try:
        s = socket.socket()
        s.connect((zproxy_ip, 22225))
        s.send(bytes(CONNECT, "utf-8"))
        resp = s.recv(4096)

        cid = re.findall("cp[0-9]+", resp.decode('utf-8'))[-1]
        # print ("cid: %s, url: %s, isDuplicate: %s" % (cid, url,  cid in cid_set))
        if (cid in cid_set):
            return ('duplicate', None, None)

        socket.setdefaulttimeout(8)

        # context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=url)

        subdomain = None

        if ("ec2" in url):
            subdomain = "G%03d%s" % (int(zproxy_id), session)
            s.send(bytes("GET /path/%s HTTP/1.1\r\nHost: %s\r\n\r\n" % (subdomain, url), "utf-8"))
            s.recv(4096)

        certs = s.getpeercertchain(binary_form=True, validate=False)
        return (certs, resp.decode("utf-8"), subdomain)

    except Exception as e:
        print(e)
        return (None, None, None)


def preloadAnswerCertificates():
    ##print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))
    certs = {}
    PATH = "/home/tjchung/research/luminati/cert_crawl/certs/answer"

    """
    ### 1. load all countries certificates
    for country in os.listdir(os.path.join(PATH, "country")):
        ccode = country.split("_")[0].lower()
        for cert in os.listdir(os.path.join(PATH, "country", country)):
            rank, url, cert_idx = cert.split("_")
            if(url not in map(operator.itemgetter(1), COUNTRY_POPULAR_WEBSITE[ccode])):
                continue ## to save memory

            if( url not in certs ):
                certs[url] = []
            certs[url].append( open(os.path.join(PATH, 'country', country, cert), "rb").read() )
    """

    ### 2. load all university, badssl, ec2 certificates
    for folder in ["university", "ec2", "badssl"]:
        for cert in os.listdir(os.path.join(PATH, folder)):
            if (os.path.isdir(os.path.join(PATH, folder, cert))):
                continue

            url, cert_idx = cert.split("_")
            if (url not in certs):
                certs[url] = []
            certs[url].append(open(os.path.join(PATH, folder, cert), "rb").read())

    return certs


def isSameCerts(certs, url):
    ##print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))
    if (type(certs) == tuple):
        for cert in certs:
            if (cert not in ANSWER_CERTS[url]):
                return False
        return True
    else:
        if (certs not in ANSWER_CERTS[url]):
            return False
        return True


def saveCertificates(certs, ccode, url, resp, subdomain):
    # print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))
    PATH = '/home/tjchung/research/luminati/cert_crawl/certs/scrape'

    month = date.today().month
    day = date.today().day
    fname = "%02d%02d" % (month, day)

    w_diff_certs = open(os.path.join(PATH, "%s.%s.diff.csv" % (fname, ccode)), "a")
    w_same_certs = open(os.path.join(PATH, "%s.%s.same.csv" % (fname, ccode)), "a")

    valid = True

    if (subdomain is None):
        ec2_subdomain = -1
    else:
        ec2_subdomain = subdomain

    if ("ec2" in url or "badssl" in url):

        for cert in certs:
            cid = re.findall("cp[0-9]+", resp)[-1]
            ip = re.findall("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", resp)[-1]
            cert_idx = certs.index(cert)
            if (isSameCerts(cert, url)):
                cert = base64.b64encode(cert).decode("utf-8")
                w_same_certs.write("%s,%s,%s,%s,%s,%s\n" % (cid, ip, url, cert_idx, cert, ec2_subdomain))

            else:
                valid = False
                cert = base64.b64encode(cert).decode("utf-8")
                w_diff_certs.write("%s,%s,%s,%s,%s,%s\n" % (cid, ip, url, cert_idx, cert, ec2_subdomain))

    else:  ## normal certs
        cid = re.findall("cp[0-9]+", resp)[-1]
        ip = re.findall("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", resp)[-1]

        if (checkValidity(certs)):
            for cert in certs:
                cert_idx = certs.index(cert)
                cert = base64.b64encode(cert).decode("utf-8")
                w_same_certs.write("%s,%s,%s,%s,%s,-1\n" % (cid, ip, url, cert_idx, cert))
        else:
            valid = False
            for cert in certs:
                cert_idx = certs.index(cert)
                cert = base64.b64encode(cert).decode("utf-8")
                w_diff_certs.write("%s,%s,%s,%s,%s,-1\n" % (cid, ip, url, cert_idx, cert))

    w_same_certs.close()
    w_diff_certs.close()

    return valid


def getTestWebsites(ccode):
    # print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))
    testWebsites = []

    ### One from our site
    testWebsites.append("ec2-52-70-160-126.compute-1.amazonaws.com")

    ### One from Alexa
    certs = COUNTRY_POPULAR_WEBSITE[ccode]
    one_cert = certs[random.randint(0, len(certs) - 1)]
    # ('9', 'www.commbank.com.au', ['9_www.commbank.com.au_1.der'])
    url = one_cert[1]
    testWebsites.append(url)

    ### One from university
    testWebsites.append(UNIVERSITY_WEBSITE[random.randint(0, len(UNIVERSITY_WEBSITE) - 1)])

    return testWebsites


def getFullTestWebsites(ccode):
    # print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))

    testWebsites = []
    ### One from our site
    testWebsites.append("ec2-52-70-160-126.compute-1.amazonaws.com")

    ### From Alexa Top 20
    certs = COUNTRY_POPULAR_WEBSITE[ccode]
    for rank, url, certs in certs:
        testWebsites.append(url)

    ### From University
    testWebsites.extend(UNIVERSITY_WEBSITE)

    ### From BadSSL
    testWebsites.extend(['expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com'])

    return testWebsites


def fetch(scraper_id):
    global cid_set

    # print ('%s, %s' % (time.ctime(), inspect.stack()[0][3]))
    ccode_list = getCountryList(100)
    ##print ("%s joined " % scraper_id )
    turn = 0
    SESSION_COUNTRY = 10
    while (True):
        my_zproxy_ips = list(filter(lambda v: ((int(v[0]) % POOL_SIZE) == scraper_id), zproxy_ips))
        zproxy_id, zproxy_ip = my_zproxy_ips[int((turn / 10) % len(my_zproxy_ips))]
        session_list[zproxy_id] = session_list.get(zproxy_id, 0)
        session = session_list[zproxy_id]
        ccode = ccode_list[int((turn / SESSION_COUNTRY) % len(
            ccode_list))]  ## at least 100 sequential proving per ccode (country_code)

        if (ccode not in COUNTRY_POPULAR_WEBSITE):
            session_list[zproxy_id] += 1
            turn += 1
            continue

        prev_cid = 0
        invalid_flag = False
        wrapsocketdown = False
        ##1. First Partial Test
        partial_test_suites = getTestWebsites(ccode)
        valid_logs = []
        try:
            if (isDuplicateCID(ccode, session, zproxy_ip, zproxy_id)):
                print("duplicate ID")
                raise

            for url in partial_test_suites:
                certs, resp, subdomain = getCertificate(url, port, ccode, session, zproxy_ip, zproxy_id, 3)
                if (certs is None):
                    wrapsocketdown = True
                    continue

                elif (certs == "duplicate"):
                    break

                cid = re.findall("cp[0-9]+", resp)[-1]

                if (prev_cid != cid and prev_cid != 0):  ## Super Proxy assigns a different exit node
                    break

                prev_cid = cid

                if ("ec2" in url or "badssl" in url):
                    isSame = isSameCerts(certs, url)
                    # print ("%s, %s" % (url, isSame))
                    if (not isSame):
                        invalid_flag = True
                        break

                else:  ## normal websites
                    isValid = checkValidity(certs)
                    # print ("%s, %s" % (url, isValid))
                    if (not isValid):
                        invalid_flag = True
                        break

                valid_logs.append((url, certs, subdomain))

            ##2. Second Full Test
            if (not invalid_flag and len(valid_logs) == 3):  ## normal case
                # print ('ALL VALID and save certs: %s' % cid)
                for url, certs, subdomain in valid_logs:
                    saveCertificates(certs, ccode, url, resp, subdomain)

                cid_set.add(cid)  ## if it passes all the cid test, we added

            if (invalid_flag):
                full_test_suites = getFullTestWebsites(ccode)

                for url in full_test_suites:
                    certs, resp, subdomain = getCertificate(url, port, ccode, session, zproxy_ip, zproxy_id, 3)
                    if (certs is None):
                        wrapsocketdown = True
                        continue

                    cid = re.findall("cp[0-9]+", resp)[-1]

                    if (prev_cid != cid):
                        break

                    prev_cid = cid
                    valid = saveCertificates(certs, ccode, url, resp, subdomain)
                    # print ( valid )

                cid_set.add(cid)  ## if it passes all the cid test, we added
                # print ("ALL 20 + 4  CERTIFICATES TEST PASSED")

        except:
            pass

        session_list[zproxy_id] += 1
        turn += 1


TOPN = 20
COUNTRY_POPULAR_WEBSITE = getTopNSites(TOPN)
UNIVERSITY_WEBSITE = open('/home/tjchung/research/luminati/alexa_crawl/university/list.dat').read().split('\n')[:-1]
UNIVERSITY_WEBSITE.remove("twin-cities.umn.edu")
ANSWER_CERTS = preloadAnswerCertificates()
cid_set = readCIDList()

if __name__ == "__main__":
    pool = Pool(POOL_SIZE)
    for scraper_id in range(0, POOL_SIZE):
        print(scraper_id)
        pool.spawn(fetch, scraper_id)
    pool.join()
