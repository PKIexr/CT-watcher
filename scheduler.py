#!/usr/bin/env python3
# coding=utf-8

import os
import tool
import config
import threading
from processor.censys_ import Censys
from processor.crt_sh_ import CrtSh
from processor.facebook_ import Facebook
from processor.google_ import Google
from processor.sslmate_ import SSLMate


class Scheduler:

    def __init__(self):
        self.monitors = [Censys(), CrtSh(), Facebook(), Google(), SSLMate()]
        for monitor in self.monitors:
            if monitor.name not in config.MONITOR_INVOLVED:
                self.monitors.remove(monitor)
        self.__new_folder()

    def data_collector(self):
        for domain in tool.domains():
            print(domain)
            thread_list = []
            for monitor in self.monitors:
                thread_ = threading.Thread(target=monitor.processor, args=(domain,))
                thread_list.append(thread_)
                thread_.start()
            for thread_ in thread_list:
                thread_.join()

    def __new_folder(self):
        self.__mkdir(config.DATA_ROOT_FOLDER)
        self.__mkdir(tool.reference_folder())
        for monitor in config.MONITOR_INVOLVED:
            self.__mkdir(config.DATA_ROOT_FOLDER + monitor)
            self.__mkdir(tool.folder(monitor, tool.RAW_DATA_FOLDER))
            self.__mkdir(tool.folder(monitor, tool.PROCESSED_CERT_FOLDER))
            self.__mkdir(tool.folder(monitor, tool.INCONSISTENT_CERT_FOLDER))
            self.__mkdir(tool.folder(monitor, tool.ANALYSIS_FOLDER))

    @staticmethod
    def __mkdir(folder_name):
        try:
            os.mkdir(folder_name)
        except FileExistsError:
            pass

