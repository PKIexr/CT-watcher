#!/usr/bin/env python3
# coding=utf-8

import os
import tool
import config
import threading
from processor.censys_ import Censys
from processor.crt_sh_ import CrtSh
from processor.entrust_ import Entrust
from processor.facebook_ import Facebook
from processor.google_ import Google
from processor.sslmate_ import SSLMate


class Scheduler:

    def __init__(self, period):
        self.monitors = [Censys(), CrtSh(), Entrust(), Facebook(), Google(), SSLMate()]
        for monitor in self.monitors:
            if monitor.name not in config.MONITOR_INVOLVED:
                self.monitors.remove(monitor)
        self.cur_period = period
        self.__mkdir(config.DATA_ROOT_FOLDER)
        self.__mkdir(tool.reference_folder())

    def data_collector(self):
        self.__new_folder(self.cur_period)
        for domain in tool.domains():
            print(domain)
            thread_list = []
            for monitor in self.monitors:
                thread_ = threading.Thread(target=monitor.processor, args=(self.cur_period, domain))
                thread_list.append(thread_)
                thread_.start()
            for thread_ in thread_list:
                thread_.join()
        self.cur_period += 1

    def __new_folder(self, period):
        self.__mkdir(config.DATA_ROOT_FOLDER + str(period))
        for monitor in config.MONITOR_INVOLVED:
            self.__mkdir(config.DATA_ROOT_FOLDER + str(period) + "/" + monitor)
            self.__mkdir(tool.folder(period, monitor, tool.RAW_DATA_FOLDER))
            self.__mkdir(tool.folder(period, monitor, tool.PROCESSED_CERT_FOLDER))
            self.__mkdir(tool.folder(period, monitor, tool.IRRELEVANT_CERT_FOLDER))
            self.__mkdir(tool.folder(period, monitor, tool.MISSING_CERT_FOLDER))
            self.__mkdir(tool.folder(period, monitor, tool.ANALYSIS_FOLDER))

    @staticmethod
    def __mkdir(folder_name):
        try:
            os.mkdir(folder_name)
        except FileExistsError:
            pass

