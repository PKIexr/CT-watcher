#!/usr/bin/env python3
# coding=utf-8

DATA_ROOT_FOLDER = "data/"

PERIOD_NUM = 1

MONITOR_INVOLVED = ["crt.sh", "Facebook", "SSLMate"]
MONITOR_CONFIG = {
    "crt.sh": {"MSD": 2, "output_limitation": 10000},
    "Facebook": {"MSD": 2, "output_limitation": 10000},
    "SSLMate": {"MSD": 2, "output_limitation": None}
}

FACEBOOK_TOKEN = ""
SSLMATE_TOKEN = ""

