#!/usr/bin/env python3
# coding=utf-8

import config
from scheduler import Scheduler
from tracker import InconsistentCertTracker
from analyzer import BugAnalyzer

if __name__ == "__main__":
    scheduler = Scheduler()
    tracker = InconsistentCertTracker()

    print("Collect certificates!!!")
    scheduler.data_collector()

    print("Construct the reference set!!!")
    tracker.construct_reference_set()

    print("Construct the inconsistent set!!!")
    for monitor in config.MONITOR_INVOLVED:
        tracker.construct_inconsistent_cert_set(monitor)
        tracker.construct_incomplete_output_set(monitor)

    print("Classify inconsistent certificates!!!")
    reference_set = tracker.reference_set()
    for monitor in config.MONITOR_INVOLVED:
        analyzer = BugAnalyzer(monitor, reference_set)
        analyzer.classify_inconsistent_cert()
