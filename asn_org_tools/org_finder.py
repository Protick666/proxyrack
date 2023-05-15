# import ujson as json
import json
import os
import time

from intervaltree import *


class AS2ISP:
    def __init__(self, path_of_asn_org=None):

        if not path_of_asn_org:
            self.raw_path = "../asn_org_tools/data/"
            self.export_path = "../asn_org_tools/data/as2isp.json"
        else:
            self.raw_path = "{}/data/".format(path_of_asn_org)
            self.export_path = "{}/data/as2isp.json".format(path_of_asn_org)


        self.date = []
        self.intervalTree = IntervalTree()
        self.as2isp = None

        self.loadDate()
        # self.check_cumulative()
        # self.saveDB()
        self.loadDB()

    def loadDate(self):
        """
        for fname in os.listdir(self.raw_path):
            if("as-rel.txt" not in fname): continue
            date = fname.split(".")[0]
            self.date.append(date)
        """
        d = []
        for fname in os.listdir(self.raw_path):
            if ("as-org2info.txt" not in fname):
                continue
            date = fname.split(".")[0]
            d.append(date)

        d.append("21000000")

        d = sorted(d)
        for prev, next in zip(d[:-1], d[1:]):
            self.intervalTree[prev:next] = prev

    def loadDB(self):
        t = time.time()
        f = open(self.export_path)
        self.as2isp = json.load(f)
        print('as2ISP DB loaded done: it took %s secs' % (time.time() - t))

    def getISP(self, date, asnum):
        """
        dbdate = self.date[min(range(len(self.date)),
            key=lambda v: abs((datetime.strptime(self.date[v], "%Y%m%d") - datetime.strptime(date, "%Y%m%d")).days))]
        #print dbdate

        """
        if (date <= min(self.intervalTree)[0]):
            date = min(self.intervalTree)[0]

        # First day
        try:
            dbdate = list(self.intervalTree[date])[0][2]
            # print("Chosen date: {}".format(dbdate))
        except Exception as e:
            a = 1

        asnum = str(asnum)
        if asnum not in self.as2isp[dbdate]:
            return "None", "None"

        org, country = self.as2isp[dbdate][asnum]
        if (country == ""): country = 'None'
        if (org == ""): org = 'None'

        return org, country
