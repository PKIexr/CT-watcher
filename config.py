#!/usr/bin/env python3
# coding=utf-8

DATA_ROOT_FOLDER = "data/"

THRESHOLD = 0.85

MONITOR_INVOLVED = ["Censys", "crt.sh", "Facebook", "SSLMate"]
MONITOR_CONFIG = {
    "Censys": {"MSD": 15, "output_limitation": 1000},
    "crt.sh": {"MSD": 6, "output_limitation": 10000},
    "Facebook": {"MSD": 4, "output_limitation": 10000},
    "SSLMate": {"MSD": 2, "output_limitation": None}
}

FACEBOOK_TOKEN = ""
SSLMATE_TOKEN = ""

