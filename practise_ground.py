import socks
import requests
import dnslib
import binascii

username = 'tijay'
password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'
PROXY_RACK_DNS = "premium.residential.proxyrack.net:9000"

def general_test():
    urlToGet = "http://ipinfo.io"
    proxy = {"http": "http://{}:{}@{}".format(username, password, PROXY_RACK_DNS)}
    r = requests.get(urlToGet, proxies=proxy)
    print("Response:\n{}".format(r.text))

# general_test()


def ip_test(url):
    # d = dnslib.DNSRecord.question("VolumeDrive.219.ttlexp.exp.net-measurement.net")
    d = dnslib.DNSRecord.question("status.rapidssl.com")
    query_data = d.pack()
    dnsPacket = query_data

    # url = "1.1.1.1"
    s = socks.socksocket()
    s.settimeout(60)
    s.set_proxy(socks.SOCKS5, 'premium.residential.proxyrack.net', 9000, True,
                username, password)

    try:
        s.connect((url, 53))
        s.send(dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket)
    except Exception as e:
        result = str(e)
        s.close()
        print(result)
    try:
        r = s.recv(1024)
        r = r.hex()
        response = binascii.unhexlify(r[4:])
        s.close()
    except:
        result = 'noResponse'
        s.close()

    result = 'success'
    parsed_result = dnslib.DNSRecord.parse(response)
    print(parsed_result)


#curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com&type=AAAA'
import json

r=requests.get("https://cloudflare-dns.com/dns-query?name=asd1.7.ttlexp.exp.net-measurement.net&type=txt", headers={"accept":"application/dns-json"})
answer = json.loads(r.text)['Answer'][0]
a = 1

try:
    print("yo")
    for i in range(100):
        ip_test('1.1.1.1')
except:
    pass


# curl -x premium.residential.proxyrack.net:9000 -U tijay:c2d49c-5bfff2-498fe7-b1f5cd-3f3212 http://api.proxyrack.net/countries/US/isps