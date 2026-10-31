# Optional ePro HCR and SlowDNS upgrades

The October 29, 2026 Linux amd64 releases are bundled under
`releases/epro-20261029/`. Their upstream READMEs are retained there.
Source announcements: https://t.me/ePro_Dev_Team/161 (SlowDNS) and
https://t.me/ePro_Dev_Team/166 (HCR).

Both binaries are UPX-packed. The repository checks their SHA-256 hashes;
these are locally calculated integrity pins, not publisher signatures:

| Binary | SHA-256 |
| --- | --- |
| hcr-server | d752aba7081672cc54ec97e4e21d5fe21ec33a2f4872c753e2638aec5beee124 |
| slowdns | a9d19e39ae23261628e8f21dac79548b31dceb45f959017bc50300e7ebfcad7d |

Fresh installs retain the previous pinned binaries until client compatibility
is established on a VPS. Existing services must be active and enabled before
an upgrade. No upstream installer is executed.

## HCR

Run from the repository as root on Linux amd64:

```bash
git pull --ff-only origin main
HCR_DIAGNOSTICS_INTERVAL=10s HCR_SESSION_STATS_INTERVAL=30s \
  bash ./apply-epro-updates.sh hcr
bash ./hcr-audit.sh
```

Both installed production HCR services are upgraded together; a service that
was never installed is skipped. Plain/TLS ports, SSH target, certificate paths,
unit protections and resource limits are preserved. The existing frame/poll
settings are retained (fresh defaults remain 6144 bytes and 8s).

Optional environment settings:

- `HCR_MAX_CONNECTIONS`, `HCR_MAX_SESSIONS`, `HCR_MAX_SESSIONS_PER_IP`: positive
  integers, or `0` to use binary defaults. Defaults remain unchanged; choose
  limits for the actual VPS and traffic. NAT users may share one public IP.
- `HCR_DIAGNOSTICS_INTERVAL`, `HCR_SESSION_STATS_INTERVAL`: `0` (disabled),
  or a duration from `10s` to `5m`. Logs are visible through `hcr-audit.sh`.
- `HCR_MAX_DOWNLOAD_FRAME`: 1..262140 bytes. Values above 16384 additionally
  require `HCR_ALLOW_LARGE_FRAMES=YES`, advertised binary support, and updated
  HTTP Custom clients on that listener.
- `HCR_DOWNLOAD_POLL_TIMEOUT`: positive milliseconds or seconds, e.g. `8s`.

Omitted settings retain the values in the installed unit. Set a diagnostic or
capacity setting explicitly to `0` to reset it. Requested options must be
advertised by the selected binary. The shared validator is also used for new
installations; the old binary may reject newer optional diagnostics flags.

## SlowDNS

```bash
bash ./apply-epro-updates.sh slowdns
bash ./slowdns-audit.sh
```

The binary is replaced without changing domain, key pair, response-size
environment file, SSH target, or listener. Local checks confirm keys and
backend health but cannot prove TG/GT or HTTP Custom wire compatibility or
browsing. Test login, reconnects and browsing before wider deployment.

The listener checks use systemd MainPID ownership and the selected IP families.
Fresh installs stop before key/binary changes if another process occupies the
selected UDP 53 address. A loopback-only system DNS stub is allowed when
SlowDNS binds a separate IPv4 address.

## Optional SlowDNS networking

Neither IPv6 nor NOTRACK is enabled automatically:

```bash
# Keep the original IPv4 listener; opt into scoped native nftables NOTRACK.
bash ./configure-slowdns-network.sh --dual-stack no --notrack yes

# Optional dual-stack listener; requires global IPv4 and IPv6 on the VPS.
bash ./configure-slowdns-network.sh --dual-stack yes --notrack no

# Return to the base IPv4 listener and disable NOTRACK.
bash ./configure-slowdns-network.sh --dual-stack no --notrack no
```

Dual-stack uses `:53`. A conflicting DNS stub or other listener aborts the
change without stopping it. Allow UDP 53 through provider/host IPv6 firewalls
and configure delegation/address records separately. A global IPv6 address
alone does not establish external IPv6 reachability.

NOTRACK is limited to selected assigned VPS addresses, inbound UDP destination
53 and outbound UDP source 53. It uses only `inet frimps_slowdns_notrack`,
with service start/stop hooks. It does not add firewall allow rules or NAT,
and never flushes another table. Enable only when your host permits untracked
DNS packets and this listener does not require connection-tracked DNAT/SNAT.
It is not a replacement for the legacy catch-all cleanup.

## Backups and rollback

Upgrades and network changes disconnect sessions for the selected protocol.
They save files under `/var/backups/frimps-v6/epro/` and print the exact rollback
command. Failed activation restores the previous files and starts the previous
service. For a later client compatibility failure, use that printed command:

```bash
bash ./apply-epro-updates.sh --rollback /var/backups/frimps-v6/epro/EXACT-BACKUP
```

Roll back multiple changes in reverse order. Reconnect the app after every
change; local service checks are not client browsing tests. Rollback restores
the affected binaries/unit or network configuration, not account databases,
keys, certificates or unrelated services.
