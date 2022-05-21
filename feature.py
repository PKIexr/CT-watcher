#!/usr/bin/env python3
# coding=utf-8

import re
import config


class Feature:
    def __init__(self, monitor):
        self.output_feature_list = []
        self.cert_feature_list = [self.only_monitor_google_logs, self.case_sensitive, self.email_certificate,
                                  self.redacted_domain, self.IDN_ccTLD, self.bad_on_busy_logs, self.too_many_dna_names,
                                  self.only_one_target_domain, self.short_lived_certificate]
        self.MSD = config.MONITOR_CONFIG[monitor]["MSD"]
        self.output_limitation = config.MONITOR_CONFIG[monitor]["output_limitation"]

    def output_limit(self, output):
        try:
            if output["RawDataSize"] == self.output_limitation:
                return True
            else:
                return False
        except KeyError:
            return False

    def service_delay(self, cert):
        try:
            if cert["LoggedTime"] is not None:
                if cert["SearchTime"] - cert["LoggedTime"] < 60 * 60 * 24 * self.MSD:
                    return True
            else:
                if cert["SearchTime"] - cert["NotBefore"] < 60 * 60 * 24 * self.MSD:
                    return True
                else:
                    return False
        except KeyError:
            return False

    @staticmethod
    def short_lived_certificate(cert):
        try:
            if cert["NotAfter"] - cert["NotBefore"] <= 60 * 60 * 24 * 91:
                return True
            else:
                return False
        except KeyError:
            return False

    @staticmethod
    def case_sensitive(cert):
        try:
            domain_inquired = cert["DomainInquired"]
            target_domains = cert["TargetDomain"]
            if target_domains is None:
                return False
            for domain in target_domains:
                match_part = domain[-len(domain_inquired):]
                if match_part.islower():
                    return False
            return True
        except KeyError:
            return False

    @staticmethod
    def email_certificate(cert):
        try:
            target_domains = cert["TargetDomain"]
            if target_domains is None:
                return False
            for domain in target_domains:
                if '@' not in domain:
                    return False
            return True
        except KeyError:
            return False

    @staticmethod
    def redacted_domain(cert):
        try:
            target_domains = cert["TargetDomain"]
            if target_domains is None:
                return False
            for domain in target_domains:
                if '?' not in domain:
                    return False
            return True
        except KeyError:
            return False

    @staticmethod
    def only_one_target_domain(cert):
        try:
            target_domains = cert["TargetDomain"]
            if target_domains is None:
                return False
            elif len(target_domains) == 1:
                return True
            else:
                return False
        except KeyError:
            return False

    @staticmethod
    def only_monitor_google_logs(cert):
        try:
            logs = cert["Log"]
            for log in logs:
                if "Google" in log:
                    return False
            return True
        except TypeError:
            return False

    @staticmethod
    def bad_on_busy_logs(cert):
        busy_logs = ["Google Argon 2020", "Google Pilot", "Google Rocketeer", "Google Xenon 2020", "Google Skydiver"]
        try:
            logs = cert["Log"]
            for log in logs:
                if "Google" not in log:
                    pass
                elif log not in busy_logs:
                    return False
            return True
        except TypeError:
            return False

    @staticmethod
    def IDN_ccTLD(cert):
        try:
            if re.match("^(.*.xn--[^.]*)$", cert["DomainInquired"]):
                return True
            else:
                return False
        except TypeError:
            return False

    @staticmethod
    def too_many_dna_names(cert):
        try:
            if len(cert["DomainName"]) > 200:
                return True
            else:
                return False
        except TypeError:
            return False
