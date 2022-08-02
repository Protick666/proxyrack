import subprocess
from subprocess import check_output, TimeoutExpired
import re
import dns.resolver
import ipaddress
import json

# /home/ubuntu/go/bin
bin_path = '/Users/protick.bhowmick/go/bin'

# TODO


def get_resolver_list():
    resolvers = []
    with open("data/nameservers.txt") as file:
        for line in file:
            resolvers.append(line.rstrip())

    return resolvers


def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False


def init():
    mother_dict = {}
    index = 0

    resolvers = get_resolver_list()
    a = 1
    for resolver in resolvers:
        if not is_ipv4(resolver):
            continue

        try:
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.timeout = 1
            dns_resolver.lifetime = 1
            dns_resolver.nameservers = [resolver]
            answer = dns_resolver.resolve('google.com')
        except:
            continue

        a = 1

        try:
            command = "{}/./dnsstresss -r {} -concurrency 50 -v 1231asd23.small.ttlexp.exp.net-measurement.net".format(
                bin_path, resolver)
            try:
                # output = check_output(command.split(), stderr=subprocess.PIPE, timeout=5)
                process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
                output, error = process.communicate(timeout=6)
            except TimeoutExpired:
                process.kill()
                outs, errs = process.communicate()
                txt = outs.decode()
                ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
                txt = ansi_escape.sub('', txt)
                mother_dict[resolver] = txt
                index += 1

                if index % 10 == 0:
                    with open("results/summary_{}.json".format(index), "w") as ouf:
                        json.dump(mother_dict, fp=ouf)
                    mother_dict = {}

        except:
            pass

init()