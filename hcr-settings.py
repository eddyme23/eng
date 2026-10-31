#!/usr/bin/env python3
"""Validate HCR options before a unit or running service is changed."""
import argparse
import os
import re
import shlex
import subprocess


def options(binary, existing=None):
    old = existing or {}
    values = {}
    defaults = {'max-download-frame': '6144', 'download-poll-timeout': '8s',
                'diagnostics-interval': '0', 'session-stats-interval': '0',
                'max-connections': '0', 'max-sessions': '0', 'max-sessions-per-ip': '0'}
    for key, default in defaults.items():
        values[key] = os.environ.get('HCR_' + key.upper().replace('-', '_'), old.get('--' + key, default))
    frame = values['max-download-frame']
    if not re.fullmatch(r'[1-9][0-9]{0,5}', frame) or not 1 <= int(frame) <= 262140:
        raise ValueError('HCR frame must be 1..262140 bytes')
    if not re.fullmatch(r'[1-9][0-9]{0,5}(ms|s)', values['download-poll-timeout']):
        raise ValueError('HCR poll timeout must use positive milliseconds or seconds')
    help_text = None
    def help_output():
        nonlocal help_text
        if help_text is None:
            result = subprocess.run([str(binary), '--help'], capture_output=True, text=True, timeout=10)
            help_text = result.stdout + result.stderr
            if result.returncode:
                raise ValueError('Candidate HCR binary failed --help')
        return help_text
    if int(frame) > 16384:
        if os.environ.get('HCR_ALLOW_LARGE_FRAMES') != 'YES':
            raise ValueError('Frames above 16384 require HCR_ALLOW_LARGE_FRAMES=YES and updated clients')
        limit = re.search(r'frame range: 1-([0-9]+)', help_output())
        if not limit or int(frame) > int(limit[1]):
            raise ValueError('Frame exceeds the limit advertised by the candidate binary')
    result = ['--max-download-frame', frame, '--download-poll-timeout', values['download-poll-timeout']]
    for key in ('max-connections', 'max-sessions', 'max-sessions-per-ip'):
        value = values[key]
        if not re.fullmatch(r'0|[1-9][0-9]{0,6}', value):
            raise ValueError(key + ' must be a nonnegative integer below 10000000')
        if value != '0':
            if not re.search(r'(?m)^\s*-{1,2}' + re.escape(key) + r'(?:\s|=|$)', help_output()):
                raise ValueError('Binary does not support ' + key)
            result += ['--' + key, value]
    for key in ('diagnostics-interval', 'session-stats-interval'):
        value = values[key]
        if value == '0':
            continue
        match = re.fullmatch(r'([1-9][0-9]{0,2})(s|m)', value)
        seconds = int(match[1]) * (60 if match[2] == 'm' else 1) if match else 0
        if not 10 <= seconds <= 300:
            raise ValueError(key + ' must be 0 or 10s..5m')
        if not re.search(r'(?m)^\s*-{1,2}' + re.escape(key) + r'(?:\s|=|$)', help_output()):
            raise ValueError('Binary does not support ' + key)
        result += ['--' + key, value]
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    try:
        print(shlex.join(options(args.binary)))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
