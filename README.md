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
| OpenSSH | TCP 22 |
| SSH payload / SSH WebSocket | TCP 80, 8080, 8880, 2082, 2086; WebSocket path `/` |
| SSH direct SSL and WebSocket TLS | TCP 443; WebSocket path `/` |
| BShield / OpenVPN HTTP upgrade | TCP 80, 8080, 8880; path `/openvpn` |
| BShield / OpenVPN HTTP upgrade over TLS | TCP 443; path `/openvpn` |
| OpenVPN | TCP/UDP 1194; direct SSL TCP 8433 |
| SlowDNS | UDP 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000â€“19999 |
| Hysteria 1 | UDP 20000â€“50000 |
| UDP Custom | Remaining UDP ports after dedicated reservations |
| BadVPN | Local helper 7300 |

HAProxy owns the shared public TCP ports. Nginx uses loopback 9080/9081; Dropbear uses loopback 143. TCP and UDP 443 are separate listeners.

Menu: `frimps-v6-menu` or `menu`.

Run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live` after installation. Live Debian proxy configuration and full VPN client tests remain required.

## Apply connection startup fixes to an installed server

```bash
git pull --ff-only origin main
bash ./apply-connection-fixes.sh
```

Hysteria 1 account creation accepts an authentication password or generates a random password when left blank. Use that password with the existing server obfs shown in the account details. Deprecated Hysteria 1 import links are not generated; account menu option 5 edits speeds.


## UDP ranges and SocksIP

UDP Custom exclusively uses public IPv4 UDP **50001-65535** (test port **53000**).
SocksIP UDP exclusively uses **1195-3999** (test port **2000**) and shares managed SSH accounts, passwords and expiry dates.
The upstream x86_64 Linux raw-packet binary is checksum verified and runs in a dedicated network namespace. Only the SocksIP range is forwarded into it. Its internal address is 169.254.240.2; clients use the VPS IPv4 address.
The original archive installer is not executed. Existing firewall configuration and package repositories are retained.
SocksIP requires a real VPS/client compatibility test; local checks do not establish Debian runtime support or successful client authentication.

To update an existing server (old UDP Custom ports, including 5300, stop routing to UDP Custom):

```bash
cd /root/eng
git pull --ff-only origin main
bash ./apply-udp-updates.sh
```

Open UDP 1195-3999 and 50001-65535 in the provider firewall. Use the SocksIP Android UDP mode for SocksIP and a UDP Custom client for UDP Custom.
