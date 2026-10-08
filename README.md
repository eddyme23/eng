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
| SSH payload / SSH WebSocket | TCP 80, 8080, 8880, 2082, 2086 |
| SSH direct SSL and WebSocket TLS | TCP 443 |
| BShield / OpenVPN HTTP upgrade | TCP 80, 8080, 8880; path `/openvpn` |
| BShield / OpenVPN HTTP upgrade over TLS | TCP 443; path `/openvpn` |
| OpenVPN | TCP/UDP 1194; direct SSL TCP 8433 |
| SlowDNS | UDP 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000-19999 |
| Hysteria 1 | UDP 20000-50000 |
| UDP Custom |UDP 50001-65535 |
| SocksIP | UDP 1195-3999 |
| BadVPN | Local helper 7300 |

HAProxy owns the shared public TCP ports. Nginx uses loopback 9080/9081; Dropbear uses loopback 143. TCP and UDP 443 are separate listeners.

Menu: `frimps-v6-menu` or `menu`.

Run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live` after installation. Live Debian proxy configuration and full VPN client tests remain required.

## Apply connection startup fixes to an installed server

```bash
git pull --ff-only origin main
bash ./apply-connection-fixes.sh
```

SSL Direct compatibility: after the TLS handshake, silent clients are routed to Dropbear after 250 ms so they can receive its SSH banner. Clients sending application data immediately are classified immediately; fragmented requests remain buffered without the idle fallback. HTTP/2 uses ALPN routing.


### Gateway connection handling

Run `bash ./apply-connection-fixes.sh` after updating to rebuild and restart the TLS, payload and SSH WebSocket gateways. Existing gateway sessions disconnect during the restart.

Silent SSL Direct clients fall back to SSH after 250 ms. Clients that send a prefix immediately do not wait for that timeout; incomplete prefixes have a separate 15-second limit. TLS and WebSocket backend connection attempts are limited to 5 seconds. The WebSocket HTTP header limit is 15 seconds; established sessions have no new idle timeout. WebSocket pings receive matching pongs.

To tune the silent fallback, create `/etc/frimps-v6/tlsmux.env` containing `FRIMPS_TLS_SILENT_TIMEOUT=250ms`. Add `FRIMPS_TLS_LOG_TIMING=true` for diagnostic handshake, classification and backend connection timings, then restart `frimps-v6-tlsmux`. Timing logs are off by default and visible through `journalctl -u frimps-v6-tlsmux`. A shorter fallback can misroute delayed HTTP clients to SSH.
