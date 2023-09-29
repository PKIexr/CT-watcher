#!/usr/bin/env python3
# coding=utf-8

import os
import csv
import json
import time
import config
from datetime import date, datetime
from publicsuffixlist import PublicSuffixList


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def utc_to_time(utc):
    return datetime.fromtimestamp(int(utc))


def time_to_utc(time_str, pattern="%Y-%m-%d %H:%M:%S"):
    time_array = time.strptime(time_str, pattern)
    return int(time.mktime(time_array))


def __write_json_file(file, data, start_time, end_time):
    json_data = {"start_time": start_time, "end_time": end_time, "data": data}
    with open(file, 'w') as f:
        json.dump(json_data, f, cls=ComplexEncoder, indent=2)


def __read_json_file(file, key):
    if not os.path.exists(file):
        return {}
    else:
        with open(file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            try:
                return data[key]
            except KeyError:
                return False


def write_(file, data, start_time=0, end_time=0):
    if data is False:
        return False
    if file[file.rindex('.'):] == ".json":
        __write_json_file(file, data, start_time, end_time)
    else:
        return False


def read_(file, key="data"):
    if file[file.rindex('.'):] == ".json":
        return __read_json_file(file, key)
    else:
        return False


def write_journal(subject, text):
    with open("journal.txt", 'a+') as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        f.write('\n')
        f.write(subject)
        f.write('\n')
        f.write(str(text))
        f.write('\n')
        f.write("---------------------------------------------------------------------------------------------")
        f.write('\n')


def domains():
    domains_file = csv.reader(open("domains.csv", "r"))
    psl = PublicSuffixList()
    domain_list = []
    for domain in domains_file:
        if not psl.is_public(domain[0]):
            domain_list.append(domain[0])
    return domain_list


def file_name(domain):
    return domain + ".json"


RAW_DATA_FOLDER = "RawData"
PROCESSED_CERT_FOLDER = "ProcessedCert"
IRRELEVANT_CERT_FOLDER = "IrrelevantCert"
MISSING_CERT_FOLDER = "MissingCert"
ANALYSIS_FOLDER = "ServiceLimit"


def folder(period, monitor, name):
    return config.DATA_ROOT_FOLDER + str(period) + "/" + monitor + "/" + name + "/"


def reference_folder():
    return config.DATA_ROOT_FOLDER + "Reference/"


def incomplete_output_set_file(period, monitor):
    return config.DATA_ROOT_FOLDER + str(period) + "/" + monitor + "/IncompleteOutputSet.json"


def total_output_set_file(period, monitor):
    return config.DATA_ROOT_FOLDER + str(period) + "/" + monitor + "/TotalOutputSet.json"


def inconsistent_cert_with_feature_file(period, monitor, name):
    return folder(period, monitor, ANALYSIS_FOLDER) + '/' + name + '.json'

