# Shared SSH certificate accounts across VPS servers

Use this when A is the proxy IP and the same certificate account must also be
accepted on B or C. Matching accounts authorize SSH login; they do not configure
proxy routing or choose the destination. No UDP Custom credentials are shared.

## Update each participating VPS

```bash
cd /root/eng
git pull --ff-only origin main
bash ./refresh-menu-v6.sh
```

## Create once, authorize elsewhere

On the issuing VPS (B for a B account, C for a C account, or A if centrally issuing):
create a certificate account in the existing menu, then export its PUBLIC package:

```bash
bash ./app-ssh-auth.sh shared-export ACCOUNT > /root/ACCOUNT-public.json
```

Copy that file to A and any destination that must accept this account. On each:

```bash
cd /root/eng
bash ./app-ssh-auth.sh shared-import /root/ACCOUNT-public.json
```

For copy/paste, choose option 08 on B, copy only the JSON from `{` through `}`,
then choose option 09 on A and paste it. Import starts when the complete JSON is
received; press Enter once if the pasted final line has no newline. Do not type
`END`. Repeat for C.
No file is needed with the menu. File import commands above still work.

The paste command is also available directly:

```bash
bash ./app-ssh-auth.sh shared-import --paste
```

Menu options 08 and 09 perform the same public authorization export/import. Import creates an absent
managed Linux account with a random undisclosed password and applies the scoped
certificate-only SSH policy. If A already has the same certificate account username,
import adds B's and C's public identities alongside A's own identity. It never replaces
the existing private bundle, local CA, other identities or UDP password. An existing
ordinary password account is still refused; this command is for certificate accounts.
Repeated imports of the same active identity are safe. A revoked identity cannot be
restored by import, and changing an existing identity's public key or CA is refused.
If a newly created account fails setup, inspect the error; remove that incomplete
account through certificate menu option 11 before retrying.

Each import is capped by the receiving Linux account's expiry. It prints the local
authorization expiry and never extends that OS account. To extend access, renew that
local OS account and then re-import the public authorization.

### Your A/B/C setup with the same username

Keep `eddy` on all three VPS servers. On B:

```bash
bash ./app-ssh-auth.sh shared-export eddy > /root/B-eddy-public.json
```

On C:

```bash
bash ./app-ssh-auth.sh shared-export eddy > /root/C-eddy-public.json
```

Copy only these public files to A. On A:

```bash
bash ./app-ssh-auth.sh shared-import /root/B-eddy-public.json
bash ./app-ssh-auth.sh shared-import /root/C-eddy-public.json
bash ./app-ssh-auth.sh bundle-list
```

A now accepts the three certificate identities under `eddy`. This does not make A
route SSH sessions to B/C; retain your existing proxy routing. Each identity retains
its original issuer. Do not paste private Gen bundles into the server import.

The public package contains the username, CA public key, principal identity,
account public key and authorization expiry. It contains no account private key,
CA private key, private Gen bundle, UDP password or server host key. Root imports
this package as a trust decision: verify its source, CA fingerprint and contents
through a trusted channel. It is not an independently signed enrollment token.
The imported CA is authorized only for this username and principal, with forwarding
and a forced false command. The issuer can reissue certificates for that principal;
local authorization expiry and local account expiry still cap access.

## Save proxy A once, without typing fingerprints

After updating each VPS, on A open App Certificate Accounts and choose **12**.
Copy the complete public proxy JSON. A does not need a certificate account first.
The SSH host key is read locally and checked against the installed SSH configs;
there is no network SSH fingerprint lookup. The public IPv4 is detected using
api.ipify.org. If detection fails or the proxy uses a different inbound IP, run
`bash ./app-ssh-auth.sh proxy-export --ip A_PUBLIC_IPV4` on A instead.

On B/C choose **13** and paste A's JSON. It completes automatically, without END.
Only copy this package from your trusted A console; it establishes trust in that
server's public host key. The public key and fingerprint must match before saving.
Saving replaces this VPS's previous saved proxy. It changes no accounts or SSH config.

Choose **05** on B/C, select the account, then select:

- **01 Direct:** keep the issuing VPS's host pin.
- **02 Saved proxy:** export the same account using saved A's host pin.
- **03 Direct + saved proxy:** approve both keys in one schema-2 bundle for updated apps/Gens.

No saved proxy means option 05 keeps its existing direct-export behavior. Gen and
the app need no new bundle format or app code: only the existing SSHHostKeyPin
field changes in the exported copy. Configure the actual proxy address/transport
in Gen as before; saving a proxy does not route traffic or alter profile endpoints.
B/C public account authorization must still be imported into A using **08 -> 09**.

The saved setting affects SSH certificate exports only, including their supported
SSH transports. Password accounts, other protocols, stored account bundles and
private keys are unchanged. Your working A path terminates SSH on A; if a proxy
only forwards SSH to B instead, use B's host pin (Direct).

Command-line equivalents:

```bash
bash ./app-ssh-auth.sh proxy-export
bash ./app-ssh-auth.sh proxy-save
bash ./app-ssh-auth.sh proxy-status
bash ./app-ssh-auth.sh bundle-export ACCOUNT --proxy
bash ./app-ssh-auth.sh proxy-clear
```

`proxy-clear` removes only the saved export preference. If A's host key rotates,
copy a new package from A and paste it again on B/C, then re-export to Gen.

## Gen and server host verification

Keep the ORIGINAL private Gen bundle from the issuing VPS. Its certificate,
private key, CA and identity remain unchanged. Never use the old `bundle-import`
command for sharing: that command deliberately signs a new local certificate.

The current app uses one SSH host fingerprint per bundle. On the VPS that actually
terminates SSH authentication, obtain and independently verify its configured
OpenSSH host fingerprint (default ENG installation):

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

On the issuer, export a destination-specific copy for that Gen server entry:

```bash
bash ./app-ssh-auth.sh bundle-export ACCOUNT --host-pin 'SHA256:VERIFIED_DESTINATION_FINGERPRINT'
```

This changes only the exported copy's host pin, not its user certificate or stored
bundle. Use A's pin if A terminates SSH, B's if A forwards to B, and C's if it forwards
to C. Verify the actual backend's configured host key if customized. Do not disable
host verification or copy server private host keys. For one bundle that works with both keys, use export target 03 and the updated
app/Gen builds. See [Combined host pins](MULTI-HOST-CERTIFICATES.md). Endpoint and DNS settings remain per server.

## Renewal and revocation

Renew only on the issuer using the normal certificate menu. Export the updated
private bundle to Gen and re-export/re-import the public authorization on every
replica to extend its authorization expiry. Renew a replica's local OS account
when longer access is needed (`bash ./ssh-accounts.sh renew-certificate ACCOUNT DAYS`), then re-import.
A keeps renewing/exporting its own local private bundle. Imported identities are
renewed on their original issuer. Menu list includes each identity ID and local/shared
origin. `shared-export ACCOUNT` prefers the local identity; use `--identity ID` to
export a specific shared identity when several exist.

To revoke B's shared identity on A without affecting A or C, use menu 10 or:

```bash
bash ./app-ssh-auth.sh revoke eddy certificate-account --identity B_DEVICE_ID
```

Use the identity ID printed by `bundle-list`; it is public. Revoke that identity
on every VPS that accepts it, including its issuer. Without `--identity`, revoke
prefers the local certificate when one exists; if there are several shared-only
identities, it refuses ambiguity. Deleting the Linux account revokes all its
identities. Revoking a shared identity does not lock the local account's UDP password.

Revocation removes authorization for new logins; existing authenticated sessions
are not terminated. There is no background synchronization. Revoked identities
cannot be restored by accidentally re-importing an old public package. This feature
does not change SlowDNS keys, domain, MTU, transport routing or password accounts.

## Validation limits

Local regression tests exercise real OpenSSH key/certificate generation, public-only
export, foreign-CA persistence, expiry caps, three identities under one username,
independent renewal/revocation, idempotence, changed-key/revoked identity rejection and rollback of trust/database on policy failure. SSH policy and
account operations are mocked on Windows. Live Linux SSH certificate login through
A and directly to B/C, host pin selection, reconnects, expiry/revocation and reboot
persistence must still be verified on VPS servers before broad rollout.

Saved-proxy tests use real OpenSSH keys and verify matching fingerprints, bounded
automatic paste, rejection of private bundles and altered pins, direct/proxy export
selection, and unchanged stored credentials. SSH config inspection and public-IP
lookup are mocked locally. Live option 12 IP detection, paste on B/C and subsequent
app login/browsing/reconnect through A still need VPS verification.
