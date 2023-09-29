#!/usr/bin/env python3
# coding=utf-8

import re
import tool
import time
import config
import requests
import OpenSSL
import standardize
from urllib.parse import quote_plus


class SSLMate:

    def __init__(self):
        self.name = "SSLMate"
        self.__headers = {'Connection': 'close'}
        self.__timeout = 120
        self.__interval_time = 3
        self.__sleep_time = 120

    @staticmethod
    def __login():
        token = config.SSLMATE_TOKEN
        link = requests.session()
        link.auth = (token, "")
        return link

    def search(self, domain):
        link = self.__login()
        raw_data_list = []
        url = "https://api.certspotter.com/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert".format(quote_plus(domain))
        while True:
            try:
                json_data = link.get(url, headers=self.__headers, timeout=self.__timeout)
                raw_data_page = json_data.json()
                time.sleep(self.__interval_time)
            except Exception as e:
                tool.write_journal("sslmate", e)
                continue
            if not raw_data_page:
                break
            elif "code" in raw_data_page:
                if raw_data_page["code"] == "rate_limited":
                    tool.write_journal("sslmate", "rate_limited")
                    time.sleep(self.__sleep_time)
                    continue
                elif raw_data_page["code"] == "timeout":
                    tool.write_journal("sslmate", "timeout")
                    time.sleep(self.__sleep_time)
                    continue
                else:
                    return raw_data_page
            else:
                for cert in raw_data_page:
                    cert_id = cert["id"]
                raw_data_list = raw_data_list + raw_data_page
                url = "https://api.certspotter.com/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert&after={1}".format(
                    quote_plus(domain), cert_id)
        return raw_data_list

    def standardize(self, raw_data_list, domain):
        cert_dict = dict()
        if "code" in raw_data_list:
            return cert_dict
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert["cert"]["sha256"]]
            standard_info["SerialNumber"] = self.__sn(cert["cert"]["data"])
            standard_info["DomainInquired"] = domain
            standard_info["CommonName"] = None
            standard_info["DomainName"] = cert["dns_names"]
            standard_info["TargetDomain"] = standardize.target_domain(domain, cert["dns_names"])
            standard_info["NotBefore"] = self.__utc(cert["not_before"])
            standard_info["NotAfter"] = self.__utc(cert["not_after"])
            standard_info["Issuer"] = cert["issuer"]["name"]
            standard_info["Log"] = None
            standard_info["Tag"] = None
            standard_info["LoggedFormat"] = None
            standard_info["LoggedTime"] = None
            fingerprint = standardize.fingerprint(standard_info)
            cert_dict[fingerprint] = standard_info
        return cert_dict

    @staticmethod
    def __utc(time_str):
        return tool.time_to_utc(time_str, "%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def __sn(cert_pem):
        try:
            cert_pem = "-----BEGIN CERTIFICATE-----\n" + cert_pem + "\n-----END CERTIFICATE-----"
            certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
            serial_number = certificate.get_serial_number()
        except:
            cert_pem_array = re.findall(".{96}", cert_pem)
            cert_pem_array.append(cert_pem[(len(cert_pem_array) * 96):])
            cert_pem = '\n'.join(cert_pem_array)
            cert_pem = "-----BEGIN CERTIFICATE-----\n" + cert_pem + "\n-----END CERTIFICATE-----"
            certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
            serial_number = certificate.get_serial_number()
        return str(serial_number)

    def processor(self, period, domain):
        file = tool.file_name(domain)
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        tool.write_(tool.folder(period, self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain)
        tool.write_(tool.folder(period, self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)

