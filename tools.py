import requests
import json
from collections import defaultdict

class Crawler():
    def __init__(self):
        self.username = 'tijay'
        self.password = 'c2d49c-5bfff2-498fe7-b1f5cd-3f3212'
        self.PROXY_RACK_DNS = "premium.residential.proxyrack.net:9000"

    def http_req(self, url, username=None):
        proxy = {"http": "http://{}:{}@{}".format(self.username, self.password, self.PROXY_RACK_DNS)}
        r = requests.get(url, proxies=proxy)
        return r

    def get_countries(self):
        response = self.http_req("http://api.proxyrack.net/countries")
        return json.loads(response.text)

    def get_isps_in_a_country(self, country_code):
        response = self.http_req("http://api.proxyrack.net/countries/{}/isps".format(country_code))
        isps = json.loads(response.text)
        for isp in isps:
            ip_info = self.http_req(url="http://ipinfo.io",
                                    username=self.username + "-country-{}-isp-{}".format(country_code, isp.replace(' ', '')))

            a = 1
        return json.loads(response.text)

    def get_isps_by_country(self):
        country_to_isp_list = defaultdict(lambda: list())
        country_code_list = self.get_countries()
        for country_code in country_code_list:
            country_to_isp_list[country_code] = self.get_isps_in_a_country(country_code)
        return country_to_isp_list


def shift(seq, n=0):
    a = n % len(seq)
    return seq[-a:] + seq[:-a]

print(shift([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], 14))

