import aiohttp
from aiohttp_socks import ProxyType, ProxyConnector, ChainProxyConnector, open_connection
import dnslib
import binascii

async def fetch():
    domain = "google.com"
    d = dnslib.DNSRecord.question(domain)
    query_data = d.pack()
    dnsPacket = query_data

    connector = ProxyConnector.from_url('socks5://tijay-country-BD:c2d49c-5bfff2-498fe7-b1f5cd-3f3212@premium.residential.proxyrack.net:9000')
    async with aiohttp.ClientSession(connector=connector) as session:
        r1 = await session.request(
            dnsPacket
        )
        print(r1)


async def tcp():
    domain = "google.com"
    d = dnslib.DNSRecord.question(domain)
    query_data = d.pack()
    dnsPacket = query_data

    reader, writer = await open_connection(
        proxy_url='socks5://tijay-country-BD:c2d49c-5bfff2-498fe7-b1f5cd-3f3212@premium.residential.proxyrack.net:9000',
        host='1.1.1.1',
        port=53
    )
    pack_to_send = dnslib.struct.pack('>h', len(dnsPacket)) + dnsPacket
    writer.write(pack_to_send)
    ret = await reader.read(1024)
    r = ret.hex()
    response = binascii.unhexlify(r[4:])
    parsed_result = dnslib.DNSRecord.parse(response)
    print(parsed_result)

def init():
    import asyncio
    asyncio.run(tcp())
    # a = await fetch("google.com")


init()