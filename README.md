# Multi Script

Debian 12 Recommended; run as root. The installer requests a TLS certificate for the primary domain only, using Cloudflare DNS validation.

Installation:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/eddyme23/eng/main/install-frimps.sh)
```

For a downloaded archive, extract it and run:

```bash
chmod +x *.sh
bash ./install-frimps.sh
```

## Protocols and ports

| Service | Public ports / path |
|---|---|
| OpenSSH | 22 |
| SSH WebSocket | 80, 8080, 8880, 2082, 2086 |
| SSH SSL and WebSocket TLS | 443 |
| OpenVPN Websocket | 80, 8080, 8880; path `/openvpn` |
| OpenVPN TLS | 443; path `/openvpn` |
| BHTTP | 90, 8081 |
| OpenVPN | TCP/UDP 1194; SSL 8433 |
| SlowDNS | UDP 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000-19999 |
| Hysteria 1 | UDP 20000-50000 |
| UDP Custom |UDP 50001-65535 |
| SocksIP | UDP 1195-3999 |
| BadVPN | 7300 |


Menu: `frimps-v6-menu` or `menu`.

BHTTP restarts now stop the alternate-port socket and its active proxy together before restarting the backend and reopening the socket. This avoids rebinding port 8180 while the proxy still holds it. Apply with `bash ./refresh-menu-v6.sh`, then `bash ./restart-bhttp.sh`. Service controls 9 (HCR) and 10 (BHTTP) use the maintained restart actions; their submenus accept padded option numbers. A socket-activated proxy may be inactive before the first client connection.

HCR and BHTTP no longer have separate installer submenus under Service Controls. They are included in Restart SSH services and Restart all, shown in service status, and available under View protocol logs (HCR NTLS/TLS and BHTTP). Fresh installation continues to install both by default.
