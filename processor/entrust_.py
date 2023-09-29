#!/usr/bin/env python3
# coding=utf-8

import time
import tool
import requests
import standardize
from urllib.parse import quote_plus


class Entrust:

    def __init__(self):
        self.name = "Entrust"
        self.__sleep_time = 120
        self.__timeout = 120

    def search(self, domain):
        while True:
            try:
                url = "https://ui.ctsearch.entrust.com/api/v1/certificates?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,publicKeyType,publicKeySize,validFrom,validTo,sn,ev,logEntries.logName,logEntries.timestamp,subjectCNReversed&domain={0}&includeExpired=false&exactMatch=false&limit=5000&_={1}".format(quote_plus(domain), int(round(time.time() * 1000)))
                req = requests.get(url, timeout=self.__timeout)
            except Exception as e:
                tool.write_journal("entrust", e)
                continue
            else:
                if req.status_code == 503 or req.status_code == 504:
                    time.sleep(self.__sleep_time)
                    continue
                elif req.status_code == 400:
                    return {"code": "{0} is a public suffix!!!".format(domain)}
                elif req.status_code == 200:
                    if req.text is "":
                        raw_data_list = []
                    else:
                        raw_data_list = req.json()
                        for crt in raw_data_list:
                            for item in crt["logEntries"]:
                                item.pop("entryIndex")
                            san_list = []
                            try:
                                for item in crt["san"]:
                                    san = item["valueReversed"][::-1]
                                    if san not in san_list:
                                        san_list.append(san)
                            except Exception as e:
                                tool.write_journal("entrust", e)
                                pass
                            crt["san"] = san_list
                    return raw_data_list
                else:
                    continue

    def standardize(self, raw_data_list, domain_inquired, search_start_time):
        cert_dict = dict()
        if "code" in raw_data_list:
            return cert_dict
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert["thumbprint"]]
            standard_info["SerialNumber"] = cert["sn"]
            standard_info["DomainInquired"] = domain_inquired
            standard_info["CommonName"] = None
            standard_info["DomainName"] = cert["san"]
            standard_info["TargetDomain"] = standardize.target_domain(domain_inquired, cert["san"])
            standard_info["NotBefore"] = self.__utc(cert["validFrom"])
            standard_info["NotAfter"] = self.__utc(cert["validTo"])
            standard_info["Issuer"] = cert["issuerCN"]
            standard_info["Log"] = cert["logEntries"]
            standard_info["Tag"] = None
            standard_info["LoggedFormat"] = None
            standard_info["LoggedTime"] = None
            if standard_info["NotAfter"] < search_start_time:
                continue
            fingerprint = standardize.fingerprint(standard_info)
            if fingerprint in cert_dict:
                another_cert_info = cert_dict[fingerprint]
                standard_info["SHA256"] = list(set(standard_info["SHA256"] + another_cert_info["SHA256"]))
                standard_info["LoggedFormat"] = 3
            cert_dict[fingerprint] = standard_info
        return cert_dict

    @staticmethod
    def __utc(time_str):
        time_str = time_str[0:time_str.index('+')]
        time_utc = tool.time_to_utc(time_str, "%Y-%m-%dT%H:%M:%SZ")
        return time_utc

    def processor(self, period, domain):
        file = tool.file_name(domain)
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        tool.write_(tool.folder(period, self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain, start_time)
        tool.write_(tool.folder(period, self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)
