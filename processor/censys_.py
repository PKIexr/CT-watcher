#!/usr/bin/env python3
# coding=utf-8

import re
import time
import tool
import standardize
from censys.search import CensysCertificates


class Censys:

    def __init__(self):
        self.name = "Censys"
        self.max_result = 1000
        self.fields = ["parsed.fingerprint_sha256",
                       "parsed.serial_number",
                       "parsed.subject_dn",
                       "parsed.subject.common_name",
                       "parsed.extensions.subject_alt_name.dns_names",
                       "parsed.issuer_dn",
                       "parsed.validity.start",
                       "parsed.validity.end",
                       "ct",
                       "tags"]

    def search_by_sha256(self, sha256):
        search_engine = CensysCertificates()
        search_statement = 'parsed.fingerprint_sha256:' + sha256
        for cert in search_engine.search(search_statement, fields=self.fields):
            return cert

    def search(self, domain):
        raw_data_list = []
        search_engine = CensysCertificates()
        search_statement = '(parsed.subject.common_name:"{0}" ' \
                           'OR parsed.names:"{0}" ' \
                           'OR parsed.extensions.subject_alt_name.dns_names:"{0}") ' \
                           'AND tags.raw: "unexpired" ' \
                           'AND tags.raw: "ct" ' \
                           'AND NOT ct.google_testtube.index: * ' \
                           'AND NOT ct.comodo_dodo.index: *'.format(domain)
        current_result = 1
        for cert in search_engine.search(search_statement, fields=self.fields):
            if current_result == self.max_result:
                break
            raw_data_list.append(cert)
            current_result = current_result + 1
        return raw_data_list

    def standardize(self, raw_data_list, domain):
        cert_dict = dict()
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert["parsed.fingerprint_sha256"]]
            standard_info["SerialNumber"] = cert["parsed.serial_number"]
            standard_info["DomainInquired"] = domain
            standard_info["CommonName"] = cert["parsed.subject.common_name"]
            standard_info["DomainName"] = cert["parsed.extensions.subject_alt_name.dns_names"]
            standard_info["TargetDomain"] = standardize.target_domain(domain, standard_info["DomainName"])
            standard_info["NotBefore"] = self.__utc(cert["parsed.validity.start"])
            standard_info["NotAfter"] = self.__utc(cert["parsed.validity.end"])
            standard_info["Issuer"] = cert["parsed.issuer_dn"]
            standard_info["Log"] = self.__logs(cert)
            standard_info["Tag"] = cert["tags"]
            standard_info["LoggedFormat"] = self.__logged_format(cert["tags"])
            fingerprint = standardize.fingerprint(standard_info)
            if fingerprint in cert_dict:
                another_cert_info = cert_dict[fingerprint]
                standard_info["SHA256"] = list(set(standard_info["SHA256"] + another_cert_info["SHA256"]))
                standard_info["Log"] = self.__merge_logs(standard_info["Log"], another_cert_info["Log"])
                standard_info["LoggedFormat"] = "Both"
            standard_info["LoggedTime"] = standardize.logged_time(standard_info["Log"])
            cert_dict[fingerprint] = standard_info
        return cert_dict

    def __logs(self, cert):
        log_dict = {}
        for item in cert:
            if re.match("ct.(.*).added_to_ct_at", item):
                log_name = item.split('.')[1].replace(' ', '').replace('_', '')
                log_time_str = cert[item][:19] + 'Z'
                log_time = self.__utc(log_time_str)
                log_dict[log_name] = log_time
        return log_dict

    @staticmethod
    def __logged_format(tags):
        if "precert" in tags:
            return "Pre"
        else:
            return "Final"

    @staticmethod
    def __merge_logs(log_dict_1, log_dict_2):
        for log in log_dict_2:
            if log not in log_dict_1:
                log_dict_1.update({log: log_dict_2[log]})
            elif log_dict_2[log] < log_dict_1[log]:
                log_dict_1.update({log: log_dict_2[log]})
        return log_dict_1

    @staticmethod
    def __utc(time_str):
        time_utc = tool.time_to_utc(time_str, "%Y-%m-%dT%H:%M:%SZ")
        return time_utc

    def processor(self, domain):
        file = tool.file_name(domain)
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        tool.write_(tool.folder(self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain)
        tool.write_(tool.folder(self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)

