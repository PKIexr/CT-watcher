#!/usr/bin/env python3
# coding=utf-8

import json
import time
import tool
import base64
import threading
import requests
import standardize
from urllib.parse import quote_plus


class Google:

    def __init__(self):
        self.name = "Google"
        self.__headers = {'Connection': 'Close'}
        self.__timeout = 5

    @staticmethod
    def __base64_to_sha256(sha256_base64):
        return ''.join(['%02x' % b for b in base64.b64decode(sha256_base64)])

    @staticmethod
    def __sha256_to_base64(sha256):
        return base64.b64encode(bytes.fromhex(sha256))

    def __search_cert_detail(self, sha256_base64):
        output = {}
        url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash={0}".format(quote_plus(sha256_base64))
        try:
            resp = requests.get(url, headers=self.__headers, timeout=self.__timeout)
        except Exception as e:
            tool.write_journal("google", e)
            return self.__search_cert_detail(sha256_base64)
        if resp.status_code == 404:
            return output
        elif resp.status_code == 503:
            return output
        else:
            resp = json.loads(resp.text.split("\n\n")[1])
            try:
                output.update({"sha256": self.__base64_to_sha256(sha256_base64)})
                output.update({"serialNumber": resp[0][1][0]})
                output.update({"subject": resp[0][1][1]})
                output.update({"issuer": resp[0][1][2]})
                output.update({"validFrom": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(resp[0][1][3] / 1000))})
                output.update({"validTo": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(resp[0][1][4] / 1000))})
            except Exception as e:
                tool.write_journal("google", e)
                return self.__search_cert_detail(sha256_base64)
            else:
                if resp[0][1][7] == "":
                    output.update({"dnsNames": "NA"})
                else:
                    output.update({"dnsNames": resp[0][1][7]})
                if resp[0][2] == "":
                    output.update({"CT": "NA"})
                else:
                    output.update({"CT": resp[0][2]})
            return output

    def __search_thread(self, sha256_base64_list):
        for sha256_base64 in sha256_base64_list:
            cert_detail = self.__search_cert_detail(sha256_base64)
            self.raw_data_list.append(cert_detail)

    def search(self, domain):
        token = ""
        self.raw_data_list = []
        thread_list = []
        while True:
            if token == "":
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={0}".format(
                    quote_plus(domain))
            else:
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p={0}".format(
                    quote_plus(token))
            try:
                req = requests.get(url, headers=self.__headers, timeout=self.__timeout)
            except requests.exceptions.ReadTimeout as e:
                tool.write_journal("google", e)
                continue
            except requests.exceptions.ConnectionError as e:
                tool.write_journal("google", e)
                continue
            else:
                data_str = req.text[6:]
                try:
                    data_json = json.loads(data_str)
                    sha256_base64_list = []
                    for raw_data in data_json[0][1]:
                        sha256_base64 = raw_data[5]
                        sha256_base64_list.append(sha256_base64)
                    thread_ = threading.Thread(target=self.__search_thread, args=(sha256_base64_list, ))
                    thread_list.append(thread_)
                    thread_.start()
                except Exception as e:
                    tool.write_journal("google", e)
                    continue
                else:
                    if len(data_json[0][1]) == 0:
                        break
                    else:
                        token = data_json[0][3][1]
                        if token is None:
                            break
        for thread_ in thread_list:
            thread_.join()
        return self.raw_data_list

    def search_by_sha256(self, sha256):
        sha256_base64 = self.__sha256_to_base64(sha256)
        return self.__search_cert_detail(sha256_base64)

    def standardize(self, raw_data_list, domain, start_time):
        cert_dict = dict()
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert["sha256"]]
            standard_info["SerialNumber"] = self.__sn(cert["serialNumber"])
            standard_info["DomainInquired"] = domain
            standard_info["CommonName"] = self.__cn(cert["subject"])
            standard_info["DomainName"] = cert["dnsNames"]
            standard_info["TargetDomain"] = standardize.target_domain(domain, cert["dnsNames"])
            standard_info["NotBefore"] = self.__utc(cert["validFrom"])
            standard_info["NotAfter"] = self.__utc(cert["validTo"])
            standard_info["Issuer"] = cert["issuer"]
            standard_info["Log"] = self.__logs(cert["CT"])
            standard_info["Tag"] = None
            standard_info["LoggedFormat"] = None
            standard_info["LoggedTime"] = None
            if standard_info["NotAfter"] < start_time:
                continue
            fingerprint = standardize.fingerprint(standard_info)
            if fingerprint in cert_dict:
                another_cert_info = cert_dict[fingerprint]
                standard_info["SHA256"] = list(set(standard_info["SHA256"] + another_cert_info["SHA256"]))
                standard_info["LoggedFormat"] = 3
            cert_dict[fingerprint] = standard_info
        return cert_dict

    @staticmethod
    def __sn(serial_number):
        serial_number_hex = "0x" + serial_number.replace(":", "")
        serial_number = int(serial_number_hex, 16)
        return str(serial_number)

    @staticmethod
    def __cn(subject):
        return subject[subject.index('CN=')+3:]

    @staticmethod
    def __utc(time_str):
        time_utc = tool.time_to_utc(time_str, "%Y-%m-%d %H:%M:%S")
        return time_utc - 28800

    @staticmethod
    def __logs(logs):
        log_dict = {}
        for log in logs:
            log_name = log[0].replace(' ', '').replace('_', '')
            log_dict[log_name] = log[1]
        return log_dict

    def processor(self, domain):
        file = tool.file_name(domain)
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        tool.write_(tool.folder(self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain, start_time)
        tool.write_(tool.folder(self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)

