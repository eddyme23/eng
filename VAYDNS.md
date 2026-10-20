# Native VayDNS alongside SlowDNS

The integration is optional on Linux amd64 and uses the upstream commit bundled
in the supplied TG archive: `a0ff70110d5e96686ab8f4c8e1c44cd09be07a75`.
The source archive and private Go 1.24.4 build toolchain have pinned SHA-256
checksums. Go modules are checked against the upstream go.sum; no upstream
installer, iptables redirect or unauthenticated remote SOCKS proxy is used.

## Existing server: start with one VPS

Create an NS delegation for a **different, non-overlapping** tunnel domain.
For the France example in this deployment:

| DNS type | Name | Target |
|---|---|---|
| A (DNS only) | fr.vpnguruz.store | 81.17.97.202 |
| NS | v-fr.vpnguruz.store | fr.vpnguruz.store |

Keep the existing SlowDNS delegation for `ns-fr.vpnguruz.store`.
The NS delegation is a DNS-provider change; the installer does not create it.
Do not create an A/CNAME at the delegated VayDNS tunnel name.

```bash
cd /root/eng
git pull --ff-only origin main
bash ./vaydns-install.sh v-fr.vpnguruz.store
```

The build can take several minutes and requires HTTPS access for downloads.
SlowDNS remains running while downloads, build and validation run. Activation
briefly disconnects SlowDNS sessions. It creates a named systemd override for
SlowDNS's listener; existing keys, account authentication and MTU stay intact.
A failure during the live activation restores the original SlowDNS endpoint.
The installer prints the manual rollback command and backup directory.

```text
VPS IPv4 UDP 53 -> DNS dispatcher
                  existing SlowDNS domain -> 127.0.0.1:5301 -> SSH 22
                  new VayDNS domain       -> 127.0.0.1:5302 -> SSH 22
```

The dispatcher forwards DNS packets unchanged, including EDNS and case. It has
bounded outstanding queries, checks backend response IDs, refuses unrelated
names, and performs no recursion or caching. Only the public IPv4 address is
bound, leaving systemd-resolved's loopback DNS stubs available. Both backends
are private. Existing native nftables UDP 53 reservation remains unchanged.
The installer aborts if the existing SlowDNS audit finds a legacy UDP catch-all;
repair it using `apply-legacy-udp-fix.sh` before retrying.

## TG Gen configuration

Add `VayDNS + SSH` as a supported server mode with:

- VaydnsDomain: the new VayDNS tunnel domain.
- VaydnsPublicKey: the new key printed by the installer/audit.
- VaydnsUsername / VaydnsPassword: an existing valid SSH account on that VPS.
- VaydnsRecordType: `txt`.
- VaydnsCompat: **false / OFF** for this native server.

Start with one working UDP carrier resolver (for example `8.8.8.8:53`) in a
VayDNS + SSH tweak. Keep advanced client fields at defaults initially. Carrier
resolver settings remain separate from browsing DNS. DoT/DoH are client-side
ways to reach recursive resolvers; this installer does not bind public 853 or
add a DoH HTTP endpoint. Existing SlowDNS and VayDNS compatibility profiles
retain their old domain/key and continue to target the SlowDNS backend.

## Operations

```bash
bash ./vaydns-audit.sh
bash ./slowdns-audit.sh
bash ./protocol-health-v6.sh --live
journalctl -u frimps-vaydns -u frimps-dns-dispatch --since '5 minutes ago' --no-pager
```

Units are enabled at boot, included in service status, UDP/all restarts and
protocol log menus. The health monitor checks private listeners and public
UDP 53. Managed backups include /etc/frimps-vaydns. SSH creation output includes
the native VayDNS domain/key. VayDNS users share SSH account expiry/deletion.

Fresh installs prompt for a VayDNS domain; blank skips this optional feature.
An explicit `V6_VAYDNS_DOMAIN` supplies the prompt's default. Fresh installation
requires the same extra NS delegation and enables/validates both added units.

Rollback (use the exact backup directory printed during installation):

```bash
bash ./rollback-vaydns.sh /var/backups/frimps-v6/vaydns-XXXXXXXX
```

Rollback removes only this integration's units/override/state, restores public
SlowDNS service, and retains both key pairs. Reconnect old SlowDNS clients.

## Validation and limitations

Packet tests cover both routes, mixed-case QNAMEs, EDNS preservation, concurrent
identical DNS IDs, unknown-domain refusal, malformed packets, overload and
configuration restrictions. The pinned server cross-builds for Linux amd64.
A local encrypted TCP echo test passed through the dispatcher for native and
DNSTT-compatible upstream server/client modes. This does not replace Debian
systemd activation, Android socket-protection, SSH password/expiry, carrier
resolver or browsing tests. Test both phone profiles, repeated reconnects and
boot persistence on one VPS before installing on the other servers.

The dispatcher adds a shared dependency for both DNS tunnels. It is supervised
by systemd and supports rollback, but cannot guarantee availability under high
load; measure throughput and reconnect behavior with your carrier network.
