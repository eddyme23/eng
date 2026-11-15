# App device certificates alongside password clients

ENG can issue operator-approved **OpenSSH user certificates** for the app's
SSH-based transports. Existing password authentication, passwords, ports,
SSH daemon configuration, TLS certificates and DNSTT keys are unchanged.
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
  access is introduced. Symlinks, unsafe ownership/write permissions and
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
Existing password holders can edit their own authorized_keys; this feature
does not turn shared password accounts into a hardened app-only boundary.

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
