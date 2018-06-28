#!/bin/python3
# -*- coding: utf-8 -*-
import Router
import AliDns
import logging


ROUTER_PASSWORD = "-"
ALIDNS_ACCESS_ID = "-"
ALIDNS_ACCESS_TOKEN = "-"
ALIDNS_SUBDOMAIN = "my.example.com"


if __name__ == "__main__":
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    format = logging.Formatter("[%(asctime)s][%(levelname)s][%(module)s:%(funcName)s:%(lineno)d] %(message)s")

    output = logging.StreamHandler()
    output.setLevel(logging.INFO)
    output.setFormatter(format)
    logger.addHandler(output)

    wan_ips = Router.get_wan_status(ROUTER_PASSWORD)
    logging.info("Get wan ips: %s", ",".join(wan_ips))

    AliDns.util_replace_records_A(ALIDNS_ACCESS_ID, ALIDNS_ACCESS_TOKEN, ALIDNS_SUBDOMAIN, wan_ips)
