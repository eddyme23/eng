# Frimps Multi Script

Debian 12, run as root. Supported protocols: SSH (payload, WebSocket and TLS), SlowDNS, UDP Custom / BadVPN, OpenVPN, WireGuard, Hysteria 1, Hysteria 2 and ZiVPN.

Extract this archive, enter its directory, then run:

```bash
chmod +x *.sh
bash ./install-frimps.sh
```

Use this complete local copy. A raw upstream installer may contain a different version.

Menu commands: `frimps-v6-menu` or `menu`.
State: `/etc/frimps-v6`. Runtime: `/usr/local/lib/frimps-v6`.

HAProxy owns TCP 443, 80, 8080, 8880, 2082 and 2086. Plain `/openvpn` WebSocket requests on 80/8080/8880 go to the local OpenVPN gateway at 10081. Other plain payloads go to the SSH payload gateway. TCP 443 goes through the TLS multiplexer for SSH TLS and WebSocket access. UDP routing and reservations retain their existing priority.

This package targets a fresh server. Existing deployments using the previous service and state paths require a separate migration; this installer does not uninstall existing server software or migrate accounts.

Validation: all shell files passed `bash -n`; removed protocol references and companion script references were checked. Live Debian service startup, HAProxy/Nginx validation and client connectivity still require VPS testing. After installation run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live`.
