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

### Optional HTTP Custom HCR trial (Linux amd64)

This is a separate plain HCR listener on TCP 8881, forwarding to OpenSSH 22. It uses existing SSH accounts and does not change eng's shared ports or default installation. Use HTTP Custom v7.10.12 (808) or newer in HCR plain mode, with the direct VPS IPv4 and port 8881; this is not a WebSocket profile.

Upload the developer-supplied `hcr-server` file to `/root/hcr-server`, then run:

```bash
bash ./hcr-test-install.sh /root/hcr-server
bash ./hcr-test-audit.sh
```

The installer verifies the exact supplied binary's SHA-256, checks that the test port is free and OpenSSH is listening, and enables a restricted systemd service. The proprietary binary is not included in this repository. Allow TCP 8881 through your host/provider firewall if required. Defaults remain 6144 bytes per download frame and an 8-second download poll timeout. These settings do not establish an 8-second startup wait. Optional installer settings are `HCR_TEST_PORT`, `HCR_MAX_DOWNLOAD_FRAME` and `HCR_DOWNLOAD_POLL_TIMEOUT`; shared eng ports cannot be used for the trial.

Compare five fresh HCR connections with five WebSocket connections on the same phone network and VPS. Record time to connected, first page load, download performance and failures before changing the defaults. Service checks alone do not verify the HCR protocol or internet access.

To remove the trial (preserving its binary):

```bash
systemctl disable --now frimps-hcr-test.service
rm -f /etc/systemd/system/frimps-hcr-test.service
systemctl daemon-reload
```

### Integrated optional HCR

Run `bash ./hcr-install.sh` to download the pinned Linux amd64 binary from `eddyme23/hrc-server`, verify its SHA-256 and install HCR plain on TCP 8881. No manual upload is required. Existing `frimps-hcr-test` connections disconnect when the trial migrates to managed `frimps-hcr`; WebSocket listeners stay unchanged. The new service starts at boot and uses existing OpenSSH accounts. Defaults remain 6144-byte download frames and an 8-second polling timeout.

HCR is optional: select its installer under maintenance in the menu, or set `V6_INSTALL_HCR=1` for a fresh installation. `HCR_PORT`, `HCR_MAX_DOWNLOAD_FRAME` and `HCR_DOWNLOAD_POLL_TIMEOUT` can be set before installation. Connection details appear in new SSH account output when HCR is active. Status/restart controls and HCR logs are available in the menu; `bash ./hcr-audit.sh` gives diagnostics. Live health checks verify the service and listener, not a complete client login. Allow the HCR TCP port in any provider or host firewall when necessary.
