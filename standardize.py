#!/usr/bin/env python3
# coding=utf-8

import re


def fingerprint(standard_info):
    return standard_info["DomainInquired"] + ';' + standard_info["SerialNumber"] + ';' + str(
        standard_info["NotBefore"]) + ';' + str(standard_info["NotAfter"]) + ';' + __issuer(standard_info["Issuer"])


def __issuer(issuer):
    issuer = issuer.replace('\\', '').replace('/', '').replace('\"', '').replace(' ', '').replace(',', '')
    return issuer[issuer.index("CN="):]


def target_domain(domain_inquired, domains):
    target_domain_ = []
    reversed_domain_inquired = domain_inquired[::-1]
    for domain in domains:
        reversed_domain = domain[::-1]
        if re.match(reversed_domain_inquired, reversed_domain, re.I):
            target_domain_.append(domain)
    return target_domain_


def logged_time(log_dict):
    logged_time_ = 10000000000
    for log in log_dict:
        if log_dict[log] < logged_time_:
            logged_time_ = log_dict[log]
    return logged_time_
