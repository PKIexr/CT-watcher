#!/usr/bin/env python3
# coding=utf-8

import tool
import config


class InconsistentCertTracker:

    def construct_reference_set(self):
        for domain in tool.domains():
            file = tool.file_name(domain)
            for monitor in config.MONITOR_INVOLVED:
                folder = tool.folder(monitor, tool.PROCESSED_CERT_FOLDER)
                cert_dict = tool.read_(folder + file)
                self.__join_reference(domain, monitor, cert_dict)

    def __join_reference(self, domain, monitor, cert_dict):
        file = tool.file_name(domain)
        reference_dict = tool.read_(tool.reference_folder() + file)
        for fingerprint in cert_dict:
            cert = cert_dict[fingerprint]
            if fingerprint in reference_dict:
                cert_in_reference = reference_dict[fingerprint]
                for item in cert_in_reference:
                    if cert_in_reference[item] is None:
                        cert_in_reference.update({item: cert[item]})
                    elif item == "SHA256":
                        if len(cert[item]) == 2:
                            cert_in_reference.update({item: cert[item]})
                    elif item == "Log":
                        if cert[item] is not None:
                            cert_in_reference.update({item: self.__merge_log_list(cert_in_reference[item], cert[item])})
                    elif item == "LoggedTime":
                        if (cert_in_reference[item] is None) or (
                                cert[item] is not None and cert[item] < cert_in_reference[item]):
                            cert_in_reference.update({item: cert[item]})
                    elif item == "Vote":
                        if monitor not in cert_in_reference["Vote"]:
                            cert_in_reference["Vote"].append(monitor)
                reference_dict.update({fingerprint: cert_in_reference})
            else:
                cert["Vote"] = [monitor]
                reference_dict.update({fingerprint: cert})
        tool.write_(tool.reference_folder() + file, reference_dict)

    @staticmethod
    def __merge_log_list(log_dict_1, log_dict_2):
        for log in log_dict_2:
            if log not in log_dict_1:
                log_dict_1.update({log: log_dict_2[log]})
            elif log_dict_1[log] is None and log_dict_2[log] is not None:
                log_dict_1.update({log: log_dict_2[log]})
        return log_dict_1

    @staticmethod
    def construct_inconsistent_cert_set(monitor):
        for domain in tool.domains():
            file = tool.file_name(domain)
            inconsistent_cert_dict = {}
            processed_folder = tool.folder(monitor, tool.PROCESSED_CERT_FOLDER)
            inconsistent_folder = tool.folder(monitor, tool.INCONSISTENT_CERT_FOLDER)
            search_start_time = tool.read_(processed_folder + file, "start_time")
            search_end_time = tool.read_(processed_folder + file, "end_time")
            cert_dict = tool.read_(processed_folder + file)
            reference_dict = tool.read_(tool.reference_folder() + file)
            for fingerprint in reference_dict:
                cert = reference_dict[fingerprint]
                cert.update({"SearchTime": search_start_time})
                if (fingerprint not in cert_dict) and (cert["NotAfter"] > search_end_time):
                    if cert["LoggedTime"] is not None:
                        if cert["LoggedTime"] < search_start_time:
                            inconsistent_cert_dict.update({fingerprint: cert})
                    else:
                        if cert["NotBefore"] < search_start_time:
                            inconsistent_cert_dict.update({fingerprint: cert})
            tool.write_(inconsistent_folder + file, inconsistent_cert_dict)

    @staticmethod
    def construct_incomplete_output_set(monitor):
        incomplete_output_dict = {}
        total_output_dict = {}
        for domain in tool.domains():
            file = tool.file_name(domain)
            inconsistent_folder = tool.folder(monitor, tool.INCONSISTENT_CERT_FOLDER)
            inconsistent_cert_list = tool.read_(inconsistent_folder + file)
            inconsistent_set_size = len(inconsistent_cert_list)

            processed_folder = tool.folder(monitor, tool.PROCESSED_CERT_FOLDER)
            processed_cert_list = tool.read_(processed_folder + file)
            searchable_set_size = len(processed_cert_list)

            raw_folder = tool.folder(monitor, tool.RAW_DATA_FOLDER)
            raw_data_list = tool.read_(raw_folder + file)
            raw_data_size = len(raw_data_list)

            fingerprint = domain
            info = {}
            info.update({"ReferenceSetSize": inconsistent_set_size + searchable_set_size})
            info.update({"SearchableSetSize": searchable_set_size})
            info.update({"RawDataSize": raw_data_size})
            total_output_dict.update({fingerprint: info})
            if inconsistent_set_size != 0:
                info.update({"InconsistentSetSize": inconsistent_set_size})
                incomplete_output_dict.update({fingerprint: info})
        tool.write_(tool.total_output_set_file(monitor), total_output_dict)
        tool.write_(tool.incomplete_output_set_file(monitor), incomplete_output_dict)

    @staticmethod
    def reference_set():
        reference_set = {}
        folder = tool.reference_folder()
        for domain in tool.domains():
            file = tool.file_name(domain)
            reference_set.update(tool.read_(folder + file))
        return reference_set

