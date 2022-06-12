import socks
import dnslib
import socket
import binascii
import re
from time import sleep
import time
from multiprocessing import Pool, Manager
import pandas as pd

user = 'tijay'
password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'

invalidURLPath = '/home/weitong/rpki/result/invalidIPs/dns/'
scanIPPath = '/home/weitong/rpki/result/scan/dns/'
targetPath = '/home/weitong/rpki/result/target/dns/dns.csv'
curTargetPath = '/home/weitong/rpki/result/target/dns/'
ispFilePath = '/home/weitong/rpki/data/proxyrack/'
resultPath = '/home/weitong/rpki/result/dns/'
retryTime = 1
maxTestIPs = 100
maxExpIPs = 20
maxIPsFromSamePrefix = 5
testNodeNum = 5
expNodeNum = 10


def getFirst(data):
    if data.shape[0] <= maxIPsFromSamePrefix:
        return data
    else:
        return data.head(maxIPsFromSamePrefix)


def getUrlList(date):
    data = pd.read_csv(f'{scanIPPath}{date}.csv')
    data = data.groupby('prefix').apply(getFirst)
    ipList = data['ip'].tolist()
    data = pd.read_csv(targetPath)
    ipList = ipList + data['target'].tolist()
    ipList = list(set(ipList))
    return ipList


def getTargetUrlList(date):
    data = pd.read_csv(f'{curTargetPath}{date}.csv')
    data['profix'] = data['target'].apply(lambda x: x.rsplit('.', 1)[0])
    data = data.reset_index(drop=True)
    return data['target'].tolist()


def getISPList():
    ispData = pd.read_csv(f'{ispFilePath}isp.csv')
    ispData = ispData.dropna()
    ispList = ispData['ISP'].tolist()
    ispList = list(set(ispList))
    return ispList


def getTestISPList():
    data = pd.read_csv(f'{ispFilePath}filterISP.csv')
    filterISPList = data['isp'].tolist()
    data = pd.read_csv(f'{ispFilePath}notFilterISP.csv')
    notFilterISPList = data['isp'].tolist()
    result = list(set(filterISPList + notFilterISPList))
    return result


def sendDNSPacket(isp, port, url, session, sessionNum, dnsPacket):
    s = socks.socksocket()
    s.settimeout(60)
    s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', port, True,
                user + f'-isp-{isp}-session-{session}-timeoutSeconds-20', password)
    t = time.localtime()
    curTime = time.strftime('%Y-%m-%d:%H-%M-%s', t)
    try:
        s.connect((url, 53))
        s.send(dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket)
    except Exception as e:
        result = str(e)
        s.close()
        return [curTime, isp, port, url, result, '']
    try:
        r = s.recv(1024)
        r = r.hex()
        response = binascii.unhexlify(r[4:])
        s.close()
    except:
        result = 'noResponse'
        s.close()
        return [curTime, isp, port, url, result, '']
    result = 'success'
    return [curTime, isp, port, url, result, response]


def tryNode(targetNode, addPort=0):
    isp = targetNode['ISP']
    port = targetNode['port'] + addPort
    dnsPacket = targetNode['dns']
    session = targetNode['session']
    try:
        s = socks.socksocket()
        s.settimeout(60)
        s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', port, True,
                    user + f'-isp-{isp}-session-{session}-timeoutSeconds-20', password)
        s.connect(('52.4.120.223', 53))
        s.send(dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket)
        r = s.recv(1024)
        r = r.hex()
        binascii.unhexlify(r[4:])
        s.close()
    except:
        return False
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', port, True,
                    user + f'-isp-{isp}-session-{session}', password)
        s.connect(('52.4.120.223', 80))
        HTTPRequest = f'GET 52.4.120.223 HTTP/1.0\r\nHost: {port}.{isp}.{date}.rpkidns.luminati.netsecurelab.org\r\n\r\n'
        s.sendall(HTTPRequest.encode())
        response = s.recv(1024)
        s.close()
    except:
        return False
    if len(response) == 0:
        return False
    return True


def sendDNSwithNode(targetNode):
    isp = targetNode['ISP']
    port = targetNode['port']
    urlList = targetNode['urlList']
    dnsPacket = targetNode['dns']
    session = targetNode['session']
    sessionNum = targetNode['sessionNum']
    try:
        nodeStatus = tryNode(targetNode)
    except:
        return [False, []]
    if nodeStatus == False:
        for addPort in range(0, retryTime):
            try:
                nodeStatus = tryNode(targetNode, addPort)
            except:
                return [False, []]
            if nodeStatus:
                port = port + addPort
                break
        if port == targetNode['port']:
            return [False, []]

    result = []
    for url in urlList:
        try:
            result.append(sendDNSPacket(isp, port, url, session, sessionNum, dnsPacket))
        except:
            continue
    return [True, result]


def getTargetList(date, ispList, urlList, nodeNum):
    targetList = []
    print(f'use isp: {len(ispList)}')
    print(f'target url: {len(urlList)}')
    print(f'node Num: {nodeNum}')
    totalCount = len(urlList) * len(ispList) * nodeNum
    sessionNum = date
    print(f'total request: {totalCount}')
    for isp in ispList:
        for port in range(10000, 10000 + nodeNum * 3, 3):
            isp = isp.replace(' ', '')
            try:
                ISPName = isp.replace('.', '')
                d = dnslib.DNSRecord.question(f'{port}.{ISPName}.{date}.rpkidns.luminati.netsecurelab.org')
            except:
                continue
            query_data = d.pack()
            target = dict()
            target['ISP'] = isp
            target['port'] = port
            target['urlList'] = urlList
            target['dns'] = query_data
            target['session'] = isp
            targetList.append(target)
    return targetList


def sendDNS(date, test):
    print(f'Send DNS {date}')
    p = Pool(100)
    if test:
        print('sendDNSRq test')
        nodeNum = 5
        fileName = f'{resultPath}test/{date}.csv'
        ispList = getTestISPList()
        urlList = getUrlList(date)
        if len(urlList) > maxTestIPs:
            urlList = urlList[:maxTestIPs]
    else:
        print('sendDNSRq exp')
        nodeNum = 10
        fileName = f'{resultPath}exp/{date}.csv'
        ispList = getISPList()
        urlList = getTargetUrlList(date)
    targetList = getTargetList(date, ispList, urlList, nodeNum)
    result = p.map(sendDNSwithNode, targetList)
    p.close()
    result = pd.DataFrame(result, columns=['ok', 'result'])
    result = result[result['ok'] == True]
    result = result.drop('ok', axis=1)
    result = result.explode('result')
    result = pd.DataFrame(result['result'].tolist(), columns=['time', 'isp', 'port', 'target', 'result', 'response'])
    print('result saved!')
    result.to_csv(fileName, index=False)


if __name__ == '__main__':
    date = '202110152000'
    sendDNS(date, test=False)