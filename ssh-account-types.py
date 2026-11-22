#!/usr/bin/env python3
"""Read-only account classification, including legacy certificate accounts."""
import argparse
import json
from pathlib import Path


def classify(store, auth=Path('/etc/frimps-app-auth'), name=None):
    rows = json.loads(Path(store).read_text())
    devices_path = auth / 'devices.json'
    policy_path = auth / 'account-policy.json'
    devices = json.loads(devices_path.read_text()) if devices_path.exists() else {'version': 1, 'devices': []}
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {}
    if not isinstance(rows, list) or not isinstance(devices, dict) or devices.get('version') != 1 or not isinstance(devices.get('devices'), list) or not isinstance(policy, dict):
        raise ValueError('Invalid account metadata; refusing account management')
    names = set()
    for device in devices['devices']:
        if not isinstance(device, dict) or not isinstance(device.get('username'), str):
            raise ValueError('Invalid certificate identity metadata')
        if device.get('device') == 'certificate-account':
            names.add(device['username'])  # Revoked identities remain certificate accounts.
    if name is not None and not any(isinstance(row, dict) and row.get('name') == name for row in rows):
        rows.append({'name': name})
    result = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('name'), str) or row.get('accountType') not in (None, 'password', 'certificate'):
            raise ValueError('Invalid managed account type')
        name = row['name']
        certificate = (row.get('accountType') == 'certificate' or name in names or
                       policy.get(name) == 'certificates-only' or
                       (auth / ('bundle-' + name + '.json')).exists())
        result.append(dict(row, accountType='certificate' if certificate else 'password'))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('store', type=Path)
    parser.add_argument('--name', help='Classify a name, including reserved deleted identities')
    args = parser.parse_args()
    try:
        rows = classify(args.store, name=args.name)
        print(next(row['accountType'] for row in rows if row['name'] == args.name) if args.name else json.dumps(rows))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
