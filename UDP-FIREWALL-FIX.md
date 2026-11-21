# SlowDNS / UDP Custom catch-all repair

## Confirmed fault and trace

On 140.150.227.184 the operator confirmed that deleting this exact rule restored
SlowDNS login, browsing and streaming without app changes:

```text
-A PREROUTING -i eth0 -p udp --dport 1:65535 -j DNAT --to-destination :36717
```

The correct policy already lives in native `table ip frimps_v6_udp`: UDP 53 is
reserved and only 50001-65535 is directed to UDP Custom. This fix does not change
that table, protocol ranges, SlowDNS domain/keys/MTU/backend, SSH authentication,
or UDP Custom's password configuration.

ENG downloads the upstream Linux amd64 binary at revision
`d7bb82abb6b36f1320bc349f36c0746b335a9ff9` from
[UDP-Custom](https://github.com/mahpud896/UDP-Custom/tree/d7bb82abb6b36f1320bc349f36c0746b335a9ff9).
The inspected packed binary SHA256 is
`2a1b5584c7947feb5a02e847e09795751024f63ce7137a353c2b9c2a4282d636`.

Static inspection after UPX decompression, without executing the UDP server,
identified `dev.epro/udp-custom/app/cmd/core.Server` building iptables/ip6tables
NAT PREROUTING commands, with the full `1:65535` range and DNAT destination built
from the listening port. The function calls `core.ExecCmd` (e.g. 0x97390b,
0x973b22 and later append branches); that helper calls `os/exec.Command` and
`Cmd.Output` and logs command errors. Startup opens the UDP server before this
firewall setup, so socket readiness alone is not proof rule creation has ended.
ENG launches it as root on 36717 without an excluded-port list. This identifies
an executable startup producer, not just an obsolete shell snippet. Executing
that exact binary under the new capability policy remains a live verification.

Current ENG shell installers do not append the catch-all. They previously ran
migration after the initial service startup, but:

- cleanup incorrectly required the independent SocksIP table;
- a RemainAfterExit migration was not rerun by UDP Custom restart;
- old saved firewall files could restore the rule;
- separate update scripts duplicated migration units and could retain old hooks;
- the transport retained firewall-administration capability.

## Repair and prevention

`install-firewall-guard.sh` is the single unit/drop-in installer. Fresh UDP
installation, existing-host repair, UDP updates and menu refresh call it. It also
refreshes installed firewall updater/health companions so an older installed menu
cannot restore the old duplicated migration definition. Other menu/transport
configuration is not regenerated.

- UDP transport gets `CapabilityBoundingSet=~CAP_NET_ADMIN`, preventing it and
  its child commands from installing host firewall rules on subsequent starts.
  Other capabilities and account authentication are not replaced. Do not remove
  this restriction merely to suppress upstream iptables permission messages.
- Privileged cleanup runs before start, after the managed PID owns UDP 36717,
  and after stop. The `+` executable prefix gives only those helper commands the
  privilege needed for cleanup; the transport stays restricted.
- Native routing starts after persistent firewall restores; its post-start hook
  removes old rules before dependent VPN services proceed.
- The boot migration follows native routing and UDP Custom and precedes SlowDNS.
  It requires native UDP routing, not SocksIP.
- Restore services (netfilter-persistent, nftables, iptables, ip6tables) have
  post-start hooks; they are not newly enabled by this fix. The existing health
  check also reconciles exact stale rules, covering later external restores.
- Standard iptables-save files are filtered atomically with private backups.
  Unmatched lines, comments and other tables remain byte-for-byte intact.
  Known files: `/etc/iptables/rules.v4`, `rules.v6`, `rules.v4.legacy`,
  `rules.v6.legacy`, `/etc/iptables.rules`, `/etc/ip6tables.rules`.

The matcher accepts only NAT PREROUTING, the selected public interface, UDP,
full port range 1:65535, DNAT, and the port-only destination :36717. Optional
`-m udp`, long option aliases and saved counters are recognized. Extra source/
destination qualifiers, comments, other interfaces, other targets and legal
ranges are preserved. No chains are flushed and no unrelated forwarding/NAT
rules are retired. Supported live frontends are default, nft and legacy variants
of iptables and ip6tables. Missing NAT families are skipped; permission/listing/
deletion errors fail explicitly. No inspectable backend is reported unverified.

Arbitrary admin scripts and arbitrary native nft configuration files are not
rewritten. If another root job deliberately re-adds the rule, its source still
needs removing; the health reconciliation is a recovery layer, not a guarantee
against competing root firewall writers. IPv6 cleanup does not add IPv6 range
routing or claim IPv6 protocol support.

## Safe existing-VPS update

```bash
cd /root/eng
git pull --ff-only origin main
bash ./apply-legacy-udp-fix.sh
bash ./retire-iptables-rules.sh --check
bash ./slowdns-audit.sh
```

This backs up rules and prior managed units/drop-ins, installs hooks and executes
migration now. It does not restart a VPN or rewrite its configuration. The new
capability boundary applies at the next UDP Custom start/restart or reboot.
Old conntrack mappings may survive rule deletion: reconnect affected clients;
this updater does not flush everyone's conntrack state.

Use `V6_PUBLIC_INTERFACE=eth0` explicitly if automatic default-route interface
detection does not describe the interface where the known rule exists.

## Verification and limits

Local automated tests exercise exact matching, six backend frontends, duplicate
rules, repeated cleanup, backend errors, native policy readiness without SocksIP,
atomic persisted-rule filtering/backups, generated hooks, installer/update
integration, startup PID readiness, simulated restart and reboot restoration.
Windows file tests mock Linux ownership/mode operations where unavailable.

An additional opt-in test uses a NEW Linux network namespace, real nft/legacy
frontends and setpriv to test fresh/restart/reboot-style rule recreation and the
capability boundary. It never calls the host persistence updater or accesses
production firewall state:

```bash
ENG_RUN_FIREWALL_NS_TEST=1 python3 -m unittest discover -s tests -p legacy_udp_kernel_test.py -v
```

Windows cannot verify kernel netfilter, real systemd ordering or Linux permission
semantics. On a VPS, verify the updater, then plan a UDP Custom restart (it drops
existing UDP Custom sessions), reconnect UDP Custom and SlowDNS, and inspect the
catch-all check. Repeat after a reboot and any actual persistence restore. Check
UDP throughput as well as login. Confirm `/proc/UDP_PID/status` no longer grants
CAP_NET_ADMIN after restart. Upstream startup may log denied firewall/sysctl
operations; the managed UDP listener and actual client traffic must still pass.
Do not change SlowDNS credentials or MTU to address a firewall DNAT conflict.
