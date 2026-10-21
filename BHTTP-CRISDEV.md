# CRISDEV BHTTP-only integration

ENG installs only `bilola-server` from CristianBatero/BHTTP_CRISDEV, pinned at
`cda976b8a18a559d0941416892deceecb9a4b105`. Downloaded amd64/arm64 binaries must
match the pinned SHA-256 checksums before execution. ENG does not run upstream
setup.sh/install.sh, install XHTTP/BTUN, create certificates or alter global
TCP/firewall settings. Upstream: https://github.com/CristianBatero/BHTTP_CRISDEV

## Install or migrate

```bash
cd /root/eng
git pull --ff-only origin main
bash ./apply-bhttp-crisdev.sh
bash ./bhttp-audit.sh
```

Fresh installs use the same helper through bhttp-install.sh. The standard
apply-bhttp-updates.sh entrypoint also selects this engine.

Requested public TCP ports: **90, 8180, 8081**. Free ports are selected. A port
already owned by the managed BHTTP service or its known alternate socket/proxy
can be migrated. Unrelated or unidentified listeners are skipped and left
untouched. If no requested ports are available, installation stops before
service changes. Only selected ports are recorded and shown in the menu and
SSH account output. Provider/host firewalls must permit the selected TCP ports.

One BHTTP process binds all selected ports directly and shares session state.
The old 8180 proxy is disabled/retired after successful migration. Existing SSH
accounts and OpenSSH on loopback TCP 22 are retained. BHTTP stays plain binary
TCP; selecting port 8081 does not turn it into WebSocket, TLS or XHTTP.

The installer tests BHP1 calibration against an isolated private listener before
switching, then tests the actual public listeners locally. It preserves systemd
sandboxing, restart rate limits and a RAM-based memory ceiling. This engine has
no --max-sessions equivalent; old BHTTP_MAX_SESSIONS values are not applied.

## Rollback

Active BHTTP sessions disconnect during migration. Backups include the previous
binary, primary unit, port settings, alternate proxy/socket unit files and their
active/enabled state. Failed activation automatically restores that setup.
Manual rollback uses the exact directory printed by the helper:

```bash
bash ./apply-bhttp-crisdev.sh --rollback /var/backups/frimps-v6/bhttp-crisdev/BACKUP_DIRECTORY
```

These are migration backups, not the older HEX updater archive format. Native
BHTTP retains boot activation, protocol health checks and existing account/menu
controls. The health monitor verifies every configured native BHTTP listener.
The upstream service does not enforce country-specific access rules. Local
BHP1 and TCP relay tests do not establish connectivity on Entel, Viva, Brazilian
or Peruvian mobile networks; verify with the affected app and carrier after
migration before claiming the country-specific issue is fixed.
