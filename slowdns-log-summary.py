#!/usr/bin/env python3
"""Summarize bounded recent SlowDNS logs without inferring client identity."""
import re
import sys
from collections import Counter


def summarize(text):
    sizes = Counter(re.findall(r'FORMERR: requester payload size (\d+) is too small \(minimum (\d+)\)', text))
    count = sum(sizes.values())
    if count:
        label = 'Repeated' if count >= 3 else 'Observed'
        print(f'[WARN] {label} SlowDNS response-size rejection: {count} in the sampled recent logs.')
        for (advertised, minimum), occurrences in sizes.items():
            print(f'  Queries advertise {advertised} bytes; this server requires {minimum}: {occurrences} rejection(s).')
        print('  These queries were rejected. Their source could be a client, resolver, or unrelated probe; this log does not identify it.')
        print('  For the affected client, inspect EDNS advertisement and resolver support. Keep the server MTU unchanged until the path is tested.')
    if re.search(r'\bbegin stream\b', text):
        print('[INFO] Recent tunnel stream activity observed; it does not prove SSH login or browsing.')
    else:
        print('[INFO] No tunnel stream start observed in this log sample; a client tunnel has not been verified.')


if __name__ == '__main__':
    summarize(sys.stdin.read())
