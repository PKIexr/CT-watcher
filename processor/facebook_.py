#!/usr/bin/env python3
# coding=utf-8

import json
import time
import tool
import config
import requests
import standardize
from urllib.parse import quote_plus


class Facebook:

    def __init__(self):
        self.name = "Facebook"
        self.limit = 1000
        self.__timeout = 20
        self.__interval_time = 10
        self.__sleep_time = 20
        self.token = config.FACEBOOK_TOKEN

    def search(self, domain):
        url = "https://graph.facebook.com/v13.0/certificates?pretty=0&query={0}&limit={1}&fields=cert_hash_sha256%2Cnot_valid_before%2Cnot_valid_after%2Cdomains%2Cserial_number%2Cissuer_name&access_token={2}".format(
            quote_plus(domain), str(self.limit), self.token)
        raw_data_list = []
        page = 0
        while True:
            try:
                time.sleep(self.__interval_time)
                req = requests.get(url, timeout=self.__timeout)
                req = req.json()
            except requests.exceptions.RequestException as e:
                tool.write_journal("facebook", e)
                time.sleep(self.__sleep_time)
                continue
            except json.decoder.JSONDecodeError as e:
                tool.write_journal("facebook", e)
                continue
            except TypeError as e:
                tool.write_journal("facebook", e)
                return
            else:
                if "error" in req:
                    tool.write_journal("facebook", req["error"])
                    if req["error"]["code"] == 100 or req["error"]["code"] == 1:
                        return req["error"]
                    else:
                        time.sleep(self.__sleep_time)
                        continue
                else:
                    page = page + 1
                    raw_data_page = req['data']
                    raw_data_list = raw_data_list + raw_data_page
                    try:
                        page_info = req['paging']
                        url = page_info['next']
                    except KeyError:
                        break
        return raw_data_list

    def standardize(self, raw_data_list, domain_inquired, search_start_time):
        cert_dict = dict()
        if "code" in raw_data_list:
            return cert_dict
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert["cert_hash_sha256"]]
            standard_info["SerialNumber"] = self.__sn(cert["serial_number"])
            standard_info["DomainInquired"] = domain_inquired
            standard_info["CommonName"] = None
            standard_info["DomainName"] = cert["domains"]
            standard_info["TargetDomain"] = standardize.target_domain(domain_inquired, cert["domains"])
            standard_info["NotBefore"] = self.__utc(cert["not_valid_before"])
            standard_info["NotAfter"] = self.__utc(cert["not_valid_after"])
            standard_info["Issuer"] = cert["issuer_name"]
            standard_info["Log"] = None
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
        time_utc = tool.time_to_utc(time_str, "%Y-%m-%dT%H:%M:%S")
        return time_utc

    @staticmethod
    def __sn(serial_number):
        if serial_number[:2] == "0x":
            serial_number = int(serial_number, 16)
        else:
            serial_number = int(serial_number)
        return str(serial_number)

    def processor(self, domain):
        file = tool.file_name(domain)
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        tool.write_(tool.folder(self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain, start_time)
        tool.write_(tool.folder(self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)

