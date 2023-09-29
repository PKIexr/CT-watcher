#!/usr/bin/env python3
# coding=utf-8

import tool
import time
import schedule
import config
from scheduler import Scheduler
from tracker import InconsistentCertTracker
from analyzer import ServiceLimitAnalyzer

if __name__ == "__main__":
    watcher_scheduler = Scheduler(1)

    print("Collect certificates!!!")
    execution_time = time.strftime("%H:%M", time.localtime(time.time()+60))
    print(execution_time)
    schedule.every().day.at(execution_time).do(watcher_scheduler.data_collector)

    while True:
        if watcher_scheduler.cur_period > config.PERIOD_NUM:
            schedule.cancel_job(watcher_scheduler.data_collector)
            schedule.clear()
            break
        schedule.run_pending()
        time.sleep(1)
    print("---------------------------------------------------------------------------------------------------")

    tracker = InconsistentCertTracker()

    print("Construct the reference set!!!")
    tracker.construct_reference_set()
    print("---------------------------------------------------------------------------------------------------")

    print("Construct the irrelevant set and the missing set!!!")
    for monitor in config.MONITOR_INVOLVED:
        tracker.construct_inconsistent_cert_set(monitor)
        tracker.construct_incomplete_output_set(monitor)
    print("---------------------------------------------------------------------------------------------------")

    print("Classify missing certificates!!!")
    reference_set = tracker.reference_set()
    for monitor in config.MONITOR_INVOLVED:
        analyzer = ServiceLimitAnalyzer(monitor, reference_set)
        analyzer.classify_missing_cert()
    print("---------------------------------------------------------------------------------------------------")
    print("---------------------------------------------------------------------------------------------------")

    print("Inspection Result:")
    for monitor in config.MONITOR_INVOLVED:
        for period in range(1, config.PERIOD_NUM+1):
            print("---------------------------------------------------------------------------------------------------")
            print(monitor + ":period-" + str(period))
            inspection_result_list = tool.read_(tool.incomplete_output_set_file(period, monitor))
            for domain in inspection_result_list:
                inspection_result = inspection_result_list[domain]
                reference_set_size = inspection_result["ReferenceSetSize"]
                searched_set_size = inspection_result["SearchedSetSize"]
                missing_set_size = inspection_result["MissingSetSize"]
                if inspection_result["MissingSetSize"] > 0:
                    print(domain + ":  " + "reference set size: " + str(reference_set_size) + "; searched set size: " + str(searched_set_size) + "; missing set size: " + str(missing_set_size))


