import requests
import pandas as pd
from multiprocessing import Pool

username = 'tijay'
password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'

PROXY_RACK_DNS = 'premium.residential.proxyrack.net:9000'

def getISPList():
    ispList = []
    resultList = []
    urlToGet = 'http://api.proxyrack.net/countries'

    proxy = {'http': f'http://{username}:{password}@{PROXY_RACK_DNS}'}
    r = requests.get(urlToGet, proxies=proxy)

    for country in r.json():
        url = f'http://api.proxyrack.net/countries/{country}/isps'
        rs = requests.get(url, proxies=proxy)
        ispList.extend(rs.json())

    ispNameList = [[isp] for isp in ispList]
    result = pd.DataFrame(ispNameList, columns=['isp_name'])
    result.to_csv('ispNameList.csv', index=False)
    p = Pool(50)
    result = p.map(testISP, ispList)
    result = pd.DataFrame(result, columns=['ISP', 'Country', 'ASN'])
    result.to_csv('isp.csv', index=False)


def testISP(isp):
    isp = isp.replace(' ', '')
    usernamewISP = f"tijay-timeoutSeconds-15-isp-{isp}"
    print(usernamewISP)
    url = 'http://ip-api.com/json'
    proxy = {'http': f'http://{usernamewISP}:{password}@{PROXY_RACK_DNS}'}
    try:
        r = requests.get(url, proxies=proxy)
        country = r.json()['countryCode']
        asn = r.json()['as']
    except:
        country = ''
        asn = ''

    return [isp, country, asn]
    '''
    resultList.append([isp, country, asn])

    result = pd.DataFrame(resultList, columns=['ISP', 'Country', 'ASN'])
    result.to_csv('/home/weitong/rpki/data/proxyrack/isp.csv', index=False)
    print(result)
    return result
    '''


if __name__ == '__main__':
    getISPList()