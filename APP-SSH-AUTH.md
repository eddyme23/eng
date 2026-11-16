# App device certificates alongside password clients

ENG can issue operator-approved **OpenSSH user certificates** for the app's
SSH-based transports. Existing password authentication, passwords, ports,
TLS certificates and DNSTT keys are unchanged. The optional certificate-only
account policy below changes SSH configuration only when explicitly requested.
Nothing is enrolled automatically during installation or menu refresh.

This is a device-credential foundation, **not enforced app exclusivity**.
An exported device private key and its valid certificate work in another
compatible SSH client. The signing CLI does not verify APK identity,
Play Integrity, hardware attestation, or proof that an uploaded key was
created by your app. Enrollment approval is an operator trust decision.
Do not describe this feature as app-only enforcement in the app/generator.

## Credential model

- One per-VPS Ed25519 CA, generated on first enrollment and stored in
  `/etc/frimps-app-auth/ca` (root-only). Never include this private signing
  key in APKs, generators, config exports or public repositories.
- Each device creates its own Ed25519 or ECDSA P-256 key pair. Only its
  single-line OpenSSH **public key** is sent to the operator. ENG does not
  generate, request, retain or export the device private key.
- A device-specific random principal and signed public certificate are
  added to one existing non-system managed SSH account. Internal SSH username
  is still required, but the app need not prompt for its password.
- The account's `.ssh/authorized_keys` gets one principal-scoped CA entry.
  Existing entries are preserved. No global CA trust or root certificate
  access is introduced. Certificate-only accounts instead use a root-owned
  per-account allowlist under `/etc/ssh/frimps-app-keys/`. Symlinks, unsafe ownership/write permissions and
  hard-linked authorized_keys files are rejected before writing.
  The home must belong to the managed account; root-owned/custom homes need
  review rather than automatic permission changes.
- Certificates are forwarding-only: no PTY, agent/X11 forwarding, user RC,
  or usable shell command. The client must use direct-tcpip/SOCKS forwarding
  without opening a shell. Normal password logins retain existing behavior.
- Validity is 1–90 days (default 7), conservatively capped at midnight UTC on
  the managed account's expiry date. Clock synchronization is required. Renewing an SSH account
  does not extend an already signed certificate.

Uses the OpenSSH documented `cert-authority`, `principals`, `restrict` and
`port-forwarding` authorized_keys options, and signed certificate restrictions:
https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT
https://man.openbsd.org/ssh-keygen#CERTIFICATES

## Operator workflow

Update and refresh the menu as usual. Under **SSH Account Management → App
device certificates**, approve, list, revoke, export or audit devices.
The same operations are available from the ENG checkout:

```bash
# Create/renew a normal managed SSH account first if needed.
# Upload only the device PUBLIC key via a trusted administrative channel.
bash ./app-ssh-auth.sh audit eddy
bash ./app-ssh-auth.sh enroll eddy phone1 /root/phone1.pub --days 7 \
  > /root/eddy-phone1-app.json
bash ./app-ssh-auth.sh list
bash ./app-ssh-auth.sh export eddy phone1 > /root/eddy-phone1-app.json
bash ./app-ssh-auth.sh revoke eddy phone1
```

Enrollment is root-only and serialized with SSH account changes. It checks
OpenSSH configuration and effective transport targets before signing. Failures
writing device metadata restore the previous authorized_keys contents.
The JSON response contains only public credential material; protect delivery
and match it to the correct device regardless. There is no public enrollment
HTTP endpoint and no automatic network-based signing operation.

Revocation removes only that device's trusted principal entry, leaving password
clients and other devices alone. It takes effect on **new authentication**;
existing sessions are not disconnected. For renewal, approve the same device
public key under a new label, deliver the new certificate, then revoke the old
label. Revoked labels cannot silently be reused. Reinstalling the app normally
creates a new key and requires enrollment again.

`maintenance-v6.sh backup` includes the root-private CA and device metadata.
Back up the per-user authorized_keys files separately if backing up accounts.
This feature does not silently rotate or regenerate an incomplete CA pair.
Existing mixed/password account holders can edit their own authorized_keys;
use the separate certificate-only policy for app-specific accounts.

## TG / Gen alignment and account policy

Reviewed TG's `native/SSH-DEVICE-AUTH.md`, the production certificate parser,
and the **Audit VPN apps and AdMob parity** chat on 2026-11-16. TG currently
uses non-exportable P-256 device keys and accepts ENG's signed P-256 user
certificate with its Ed25519 signing CA. ENG still accepts Ed25519 device
public keys for other compatible certificate clients; use **P-256 for TG**.
TG's `device_certificate` profile mode differs intentionally from the
package's `openssh-user-certificate` authMethod; both formats are supported.

After enrollment, obtain the exact public policy fields required by Gen:

```bash
bash ./app-ssh-auth.sh pins app_eddy > /root/app-eddy-gen-policy.json
# If a different SSH host key is negotiated, select its configured public file:
bash ./app-ssh-auth.sh pins app_eddy --host-key /etc/ssh/ssh_host_rsa_key.pub
```

The `genPolicy` object contains `SSHAuthMethod=device_certificate`,
`SSHCertificateCA=SHA256:...`, and `SSHHostKeyPin=SHA256:...`. Fill each
transport's username with `app_eddy`; passwords may be blank for that profile.
The pin must match the **negotiated** SSH host key. The command verifies that
the chosen key is configured for both SSH backends, but does not perform the
phone's SSH negotiation. It does not change the host keys or pin bypass rules.
The enrollment JSON also provides an optional `caFingerprint` field; TG can
ignore this extra field and verifies the actual certificate and CA itself.

Keep ordinary clients on their current accounts. Create a **separate managed
SSH account** for app-specific access, enroll its P-256 device key, and test
certificate login first. Then explicitly enforce certificate-only SSH login:

```bash
bash ./app-ssh-auth.sh policy app_eddy --mode certificates-only
bash ./app-ssh-auth.sh audit app_eddy

# Revert this account to its inherited password/public-key configuration:
bash ./app-ssh-auth.sh policy app_eddy --mode mixed
```

`certificates-only` requires an unexpired approved device. It applies a scoped
OpenSSH Match rule to this username on SSH 22 and the installed loopback
backend 2222, disables password/keyboard-interactive login, requires public-key
authentication with certificate algorithms, and reads only the root-owned
principal-scoped CA allowlist. Ordinary raw public keys are not accepted there.
It does not lock or replace the system password, modify other protocol daemons,
or change another account's authentication. Accounts remain mixed by default.
Converting a shared account would prevent that account's other SSH password
clients from logging in, so use a separate app account.

The operation saves a private snapshot under
`/var/backups/frimps-v6/app-ssh-policy/`, validates syntax/effective policy,
and sends HUP to the SSH masters. Existing authenticated sessions stay open.
Failure restores the prior configuration and trust files, then attempts to
reload them; inspect any explicit recovery error from an existing admin session.
Custom conditional Match rules in the base configs or their includes require
manual review first: a localhost check cannot exclude a password exception for
another address. An effective-policy mismatch also causes failure rather than
an inaccurate success report. Rebuilding the dedicated SSH backend
preserves the policy include. Keep the include at the end of each config.

Enrollment/revocation synchronizes the central allowlist for certificate-only
accounts. Account deletion/expiry cleanup revokes devices before removing the
OS account, including removal of stale central trust. Policy remains scoped to
that username after deletion as a fail-closed measure; explicitly choose mixed
if intentionally reusing its name for password clients. Credential revocation
and policy changes affect new logins, not existing sessions. Maintenance backups
now include `/etc/ssh` (host private keys and policy), so keep them root-private.

An ENG-generated P-256 certificate was also parsed successfully by TG's actual
production `OpenSshDeviceCertificate` Java implementation (not a replacement
parser). Its CA fingerprint matches native `ssh-keygen -lf -E sha256` output.

No live Linux sshd/PAM certificate-only login or phone Keystore signing has yet
been verified by this server change. Test both certificate success and password
rejection for the app account, plus password success for an unrelated ordinary
account, through each required transport before wider rollout.

## Transport mapping

| App transport | Required SSH endpoint after transport establishment |
|---|---|
| Direct SSH | OpenSSH 22 |
| SSH WebSocket, SSL Direct, SSL WebSocket | Dedicated OpenSSH 2222 (current ENG default) |
| BHTTP, HCR NTLS/TLS | OpenSSH 22 |
| SlowDNS/DNSTT, including resolver DoH/DoT | OpenSSH 22 |

Port 2222 remains loopback-only. **Dropbear 143 cannot accept these certificates.**
On an older deployment with Dropbear-backed gateways, select the existing
dedicated backend first using `apply-ssh-capacity-fix.sh`; it disconnects
gateway sessions. Enrollment does not perform that migration automatically.
Custom SSH Match rules, host/IP restrictions, AllowedUsers and public-key
algorithm settings may still prevent authentication. Audit is a configuration
readiness check, not proof of a successful app login or browsing.

## App and generator handoff

The `enroll`/`export` output has this versioned public contract:

```json
{
  "schema": 1,
  "type": "eng-ssh-device-certificate",
  "authMethod": "openssh-user-certificate",
  "username": "eddy",
  "deviceId": "<random id>",
  "deviceLabel": "phone1",
  "publicKey": "ssh-ed25519 AAAA...",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "caPublicKey": "ssh-ed25519 AAAA...",
  "validAfter": "<UTC ISO timestamp>",
  "validBefore": "<UTC ISO timestamp>",
  "privateKeyIncluded": false
}
```

1. Add an explicit certificate account mode alongside the existing password
   mode. Preserve existing generator/profile fields and password clients.
2. Generate a unique key on the device. Prefer a non-exportable Android
   Keystore P-256 key **if** the SSH library can sign with it and support the
   ECDSA OpenSSH certificate format. Ed25519 is also accepted by ENG.
   Export SSH wire-format public keys, not PEM/X.509 SubjectPublicKeyInfo.
3. Import the approved certificate package and verify that its public key
   matches the device key. Keep the private key out of generator configs,
   JSON exports, backups, logs and APK assets. Public certificate data alone
   cannot authenticate without the corresponding private-key signature.
4. The SSH library must implement **OpenSSH user certificate authentication**
   and signing using the matching private key. Ordinary private-key auth or
   attaching the certificate as a TLS certificate does not implement this.
   Keep the existing SSH server host-key verification; `caPublicKey` here is
   a user-signing CA, not the server host key or website TLS CA.
5. Use the same credential after every supported transport handshake. Do not
   send shell/PTY requests and do not silently fall back to password auth for
   a certificate-mode profile. Show expiry/revocation errors clearly.
6. Keep registration/signing approval outside the untrusted generator. A future
   automatic enrollment service needs authenticated accounts, server-issued
   challenges, proof of possession, replay protection and verified attestation
   where required. None of those are supplied by this operator CLI.

No Android or generator code was changed here. Before release test certificate
login, TCP forwarding, wrong key/user, expiry, device revocation, reconnects,
and password-client compatibility on a Linux VPS through every transport.
Local tests use real OpenSSH certificate signing/inspection, but the Windows
development host cannot establish the Linux sshd/PAM end-to-end result.
