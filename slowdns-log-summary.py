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
    errors = re.findall(r'session ([^\s:]+).*message authentication failed', text)
    failed_sessions = set(errors)
    streams = set(re.findall(r'begin stream ([^\s:]+):', text))
    if errors:
        print(f'[WARN] Recent encrypted authentication failures: {len(errors)} in {len(failed_sessions)} session(s).')
        print('  These sessions failed tunnel authentication; logs do not identify a specific phone or prove a server fault.')
    healthy_streams = streams - failed_sessions
    if healthy_streams:
        print(f'[INFO] Stream starts observed in {len(healthy_streams)} session(s) without sampled authentication failures; this does not prove SSH login or browsing.')
    elif streams:
        print('[INFO] Stream starts only belong to sessions with sampled authentication failures; no healthy session is established by this sample.')
    else:
        print('[INFO] No stream starts in the recent log sample; absence alone is not a server fault.')


if __name__ == '__main__':
    summarize(sys.stdin.read())
