#!/usr/bin/env python3
# coding=utf-8

import tool
import config
from feature import Feature


class ServiceLimitAnalyzer:
    def __init__(self, monitor, reference_set):
        self.monitor = monitor
        self.feature = Feature(monitor)
        self.reference_set = reference_set

    def classify_missing_cert(self):
        self.__filter_off_limit_cert()
        # self.__filter_by_incomplete_output_feature()
        # self.__filter_by_inconsistent_cert_feature()

    def __filter_off_limit_cert(self):
        for period in range(1, config.PERIOD_NUM+1):
            incomplete_output_set = self.incomplete_output_set(period)
            inconsistent_cert_set = self.missing_cert_set(period)

            exclude_domain = []
            for fingerprint in incomplete_output_set:
                output = incomplete_output_set[fingerprint]
                if self.feature.output_limit(output):
                    domain = fingerprint.split(';')[0]
                    if domain not in exclude_domain:
                        exclude_domain.append(domain)
            cert_with_feature_set = {}
            for fingerprint in list(inconsistent_cert_set.keys()):
                domain = fingerprint.split(';')[0]
                cert = inconsistent_cert_set[fingerprint]
                if domain in exclude_domain:
                    inconsistent_cert_set.pop(fingerprint)
                    cert_with_feature_set.update({fingerprint: cert})
            tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, self.feature.output_limit.__name__),
                        cert_with_feature_set)

    def __filter_by_incomplete_output_feature(self):
        for period in range(1, config.PERIOD_NUM + 1):
            incomplete_output_set = self.incomplete_output_set(period)
            inconsistent_cert_set = self.remainder_set(period)
            for feature_discriminant in self.feature.output_feature_list:
                bad_domain = []
                incomplete_output_with_feature_num = 0
                output_with_feature_num = 0
                for fingerprint in incomplete_output_set:
                    output = incomplete_output_set[fingerprint]
                    if feature_discriminant(output):
                        incomplete_output_with_feature_num = incomplete_output_with_feature_num + 1
                        domain = fingerprint.split(';')[0]
                        if domain not in bad_domain:
                            bad_domain.append(domain)
                total_output_set = self.total_output_set(period)
                for fingerprint in total_output_set:
                    output = total_output_set[fingerprint]
                    if feature_discriminant(output):
                        output_with_feature_num = output_with_feature_num + 1
                if output_with_feature_num == 0:
                    continue
                if self.__discriminant_a(incomplete_output_with_feature_num, output_with_feature_num):
                    cert_with_feature_set = {}
                    for fingerprint in list(inconsistent_cert_set.keys()):
                        domain = fingerprint.split(';')[0]
                        cert = inconsistent_cert_set[fingerprint]
                        if domain in bad_domain:
                            inconsistent_cert_set.pop(fingerprint)
                            cert_with_feature_set.update({fingerprint: cert})
                    tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, feature_discriminant.__name__),
                                cert_with_feature_set)
            tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, "remainder"), inconsistent_cert_set)

    def __filter_by_inconsistent_cert_feature(self):
        for period in range(1, config.PERIOD_NUM + 1):
            inconsistent_cert_set = self.remainder_set(period)
            for feature_discriminant in self.feature.cert_feature_list:
                cert_with_feature_set = {}
                inconsistent_cert_with_feature_num = 0
                inconsistent_cert_num = 0
                cert_with_feature_num = 0
                cert_num = 0
                for fingerprint in list(inconsistent_cert_set.keys()):
                    inconsistent_cert_num = inconsistent_cert_num + 1
                    cert = inconsistent_cert_set[fingerprint]
                    if feature_discriminant(cert):
                        inconsistent_cert_with_feature_num = inconsistent_cert_with_feature_num + 1
                        cert_with_feature_set.update({fingerprint: cert})
                for fingerprint in self.reference_set:
                    cert_num = cert_num + 1
                    cert = self.reference_set[fingerprint]
                    if feature_discriminant(cert):
                        cert_with_feature_num = cert_with_feature_num + 1
                if inconsistent_cert_num == 0:
                    break
                if self.__discriminant_a(inconsistent_cert_with_feature_num, cert_with_feature_num):
                    tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, feature_discriminant.__name__),
                                cert_with_feature_set)
                    for fingerprint in cert_with_feature_set:
                        inconsistent_cert_set.pop(fingerprint)
                elif inconsistent_cert_num > 10:
                    if self.__discriminant_b(inconsistent_cert_with_feature_num, inconsistent_cert_num,
                                             cert_with_feature_num, cert_num):
                        tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, feature_discriminant.__name__),
                                    cert_with_feature_set)
                        for fingerprint in cert_with_feature_set:
                            inconsistent_cert_set.pop(fingerprint)
            tool.write_(tool.inconsistent_cert_with_feature_file(period, self.monitor, "remainder"), inconsistent_cert_set)

    @staticmethod
    def __discriminant_a(a, b):
        try:
            if a/b > 0.85:
                return True
            else:
                return False
        except ZeroDivisionError:
            return False

    def __discriminant_b(self, a, b, c, d):
        try:
            if a/b < c/d:
                return False
            else:
                return self.__cramer_v_fit(a, b-a, c/d, 1-(c/d))
        except ZeroDivisionError:
            return False

    @staticmethod
    def __cramer_v_fit(o_1, o_2, p_1, p_2):
        try:
            n = o_1 + o_2
            e_1 = n * p_1
            e_2 = n * p_2
            x = pow(o_1 - e_1, 2)/e_1 + pow(o_2 - e_2, 2)/e_2
            v = pow(x/n, .5)
            if v >= 0.5:
                return True
            else:
                return False
        except ZeroDivisionError:
            return False

    def missing_cert_set(self, period):
        inconsistent_cert_set = {}
        folder = tool.folder(period, self.monitor, tool.MISSING_CERT_FOLDER)
        for domain in tool.domains():
            file = tool.file_name(domain)
            inconsistent_cert_set.update(tool.read_(folder + file))
        return inconsistent_cert_set

    def incomplete_output_set(self, period):
        return tool.read_(tool.incomplete_output_set_file(period, self.monitor))

    def total_output_set(self, period):
        return tool.read_(tool.total_output_set_file(period, self.monitor))

    def remainder_set(self, period):
        return tool.read_(tool.inconsistent_cert_with_feature_file(period, self.monitor, "remainder"))


