# cert-enrolment

Device certificate enrolment service for the homelab trusted Wi-Fi.

`cert-enrolment` lets a member of the LDAP `device-enrollers` group register a device
and download everything that device needs to join the 802.1X (EAP-TLS)
network: a device certificate from the homelab step-ca, the Root CA, and the
Wi-Fi configuration. It runs as a rootless Podman container behind NGINX at
`join.laverick.home.arpa`, deployed by the `homelab` repository.

## How it fits together

```text
 browser on the device ──HTTPS──▶ NGINX ──HTTP──▶ cert-enrolment ──LDAPS──▶ LDAP
                                                    │              (ou=Devices,
                                                    │               device-enrollers)
                                     signs single-use tokens
                                                    │
 device ──── CSR + token (Windows, Linux) ───────▶ step-ca
 device ──── SCEP (iOS) ─────────────────────────▶ step-ca ──webhook──▶ cert-enrolment
                                                                  (challenge check)

 device ──── EAP-TLS ──▶ access point ──RADIUS──▶ FreeRADIUS ──▶ LDAP
```

`cert-enrolment` never handles a device's private key and never calls step-ca itself.
Its only outbound connection is to LDAP.

## Device identity

* Every device is `<name>.device.laverick.home.arpa`: a single label under
  the device domain. This name is the certificate Common Name and the LDAP
  `deviceId`. It is never published in DNS.
* Device entries live in `ou=Devices` as `device` + `managedDevice`
  (`deviceId`, `deviceType`, `deviceZone`, `deviceDisabled`).
* FreeRADIUS accepts a device only if its certificate chains to the homelab
  CA, carries clientAuth and not serverAuth, has a device-domain CN, and
  matches an enabled `managedDevice`. `deviceZone` selects the VLAN.

## Enrolment flow

1. A `device-enrollers` member signs in with their LDAP credentials.
2. They register a device (name, type, zone), which creates its LDAP entry.
3. On the device itself they download the enrolment material for its
   platform. Each download embeds a credential that is single-use, bound
   to that device name, and valid for about ten minutes.

| Platform | Delivered as | Key storage | Issuance | Renewal |
|---|---|---|---|---|
| Windows 11 | PowerShell script, run once as administrator | TPM (Microsoft Platform Crypto Provider), machine store | step-ca JWK provisioner, single-use token | Scheduled task, mTLS renewal against step-ca |
| Linux | Shell script | File, root-only | step-ca JWK provisioner, single-use token | systemd timer, `step ca renew` |
| iOS | `.mobileconfig` profile (Root CA + SCEP + Wi-Fi) | Keychain | step-ca SCEP provisioner, challenge checked by `cert-enrolment` webhook | Re-download from `join.laverick.home.arpa` before expiry |

The Wi-Fi configuration on every platform trusts only the homelab Root CA,
validates the RADIUS server name, and uses TLS 1.3. Linux supplicants
(wpa_supplicant 2.10) disable EAP TLS 1.3 by default, so the Linux script
enables it explicitly.

## Certificates

* 30-day lifetime on every platform.
* clientAuth only. FreeRADIUS rejects certificates that also carry
  serverAuth, which excludes ACME service certificates.
* A Windows or Linux device that stays off past expiry cannot renew and
  must be enrolled again.
* Revocation: set `deviceDisabled` in LDAP (effective at the next
  association). Revoking in step-ca additionally blocks renewal.

## Device registration

* A signed-in enroller enters a device name (one DNS label, lowercased),
  a platform (Windows, Linux or iOS) and a network zone from
  `CERT_ENROLMENT_DEVICE_ZONES`.
* The service account creates
  `cn=<label>.<device domain>,<devices DN>` with object classes `device`
  and `managedDevice`: `deviceId` (same as the CN), `deviceType` (platform),
  `deviceZone`, `deviceDisabled: FALSE`, and `owner` set to the enroller's
  DN for auditing.
* Names that already exist are refused. All enrollers see every device.
* Registrations are logged with the enroller, device, platform and zone.

## Disabling and deleting devices

* Any enroller can disable, enable or delete any device from the list.
* Disable sets `deviceDisabled: TRUE`; FreeRADIUS then rejects the device
  at its next association. Enable sets it back to `FALSE`.
* Delete removes the LDAP entry after a confirmation page (the Content
  Security Policy allows no script, so there is no browser dialog).
* Each change is logged with the enroller and device.
* Certificates are not yet revoked. A disabled or deleted device's
  certificate stays valid until it expires, but FreeRADIUS refuses it.

## Dependencies

Agreed set, each added with the feature that needs it:

| Crate | Purpose |
|---|---|
| `tiny_http` | HTTP server |
| `ldap3` | LDAP sign-in and device entries (sync API, rustls with ring; no OpenSSL) |
| `p256`, `ecdsa`, `base64`, `serde_json` | Signing step-ca single-use tokens (ES256 JWS) |

`hmac` and `sha2` were originally planned for signed session cookies. Sessions
are held in memory instead (see below), so they are not needed. Random
tokens come from `/dev/urandom`.

## Build

```
cargo build --release
```

or build the image:

```
podman build -t cert-enrolment -f Containerfile .
```

CI mirrors podwatch: `build-cert-enrolment.yaml` builds `./Containerfile` and pushes
to `ghcr.io/<owner>/cert-enrolment` (`latest` on `main`, semver tags on `v*.*.*`),
and `secret-scan.yaml` runs Gitleaks on every push and pull request.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CERT_ENROLMENT_LISTEN` | `0.0.0.0:8080` | Address and port to listen on |
| `CERT_ENROLMENT_LDAP_URL` | required | LDAP server; must be `ldaps://` |
| `CERT_ENROLMENT_LDAP_PEOPLE_DN` | required | Users sign in as `uid=<name>,<this DN>` |
| `CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN` | required | `posixGroup` whose `memberUid` values may sign in |
| `CERT_ENROLMENT_LDAP_BIND_DN` | required | Service account for reading and writing device entries |
| `CERT_ENROLMENT_LDAP_BIND_PASSWORD_FILE` | required | File holding the service account password (a Podman secret) |
| `CERT_ENROLMENT_LDAP_DEVICES_DN` | required | Container of device entries, e.g. `ou=Devices,dc=...` |
| `CERT_ENROLMENT_DEVICE_DOMAIN` | required | Device identities are `<label>.<this domain>` |
| `CERT_ENROLMENT_DEVICE_ZONES` | required | Comma-separated zones offered at registration; the first is the default. Must match the FreeRADIUS zone map |
| `CERT_ENROLMENT_SESSION_MINUTES` | `30` | Idle time before a session expires |
| `SSL_CERT_FILE` | none | PEM file of CAs trusted for LDAPS. Set it to the homelab Root CA; the image has no other trust store |

## Sign-in and sessions

* Users sign in by binding to LDAP as themselves; `device-enrollers`
  membership is then read over the same connection. Sign-in uses no service
  account. Account lockout is enforced by the directory's password policy.
* Empty passwords are refused before contacting LDAP, because an empty
  password is an anonymous bind, which LDAP accepts.
* User names are restricted to `[a-z0-9._-]`, and are escaped as well
  before use in a DN or filter.
* Sessions are random 256-bit tokens held in memory, so signing out really
  ends a session. A restart signs everyone out. Sessions expire after
  `CERT_ENROLMENT_SESSION_MINUTES` of inactivity.
* Cookies are `__Host-` prefixed, `Secure`, `HttpOnly` and
  `SameSite=Strict`. Every form carries a CSRF token; the sign-in form
  uses a double-submit cookie.
* Responses carry a restrictive Content Security Policy, `nosniff`,
  `no-referrer` and `no-store`. All page values are HTML-escaped.

## Status

* [x] Service skeleton, container image and CI
* [x] LDAP sign-in restricted to `device-enrollers`
* [x] Device registration in `ou=Devices`
* [x] Disable, enable and delete devices
* [ ] step-ca JWK provisioner and single-use token signing
* [ ] Windows enrolment script
* [ ] Linux enrolment script
* [ ] step-ca SCEP provisioner and challenge webhook
* [ ] iOS enrolment profile
* [ ] Revoke the certificate in step-ca when a device is deleted, so it cannot renew
* [ ] Expiry view for devices that renew manually (iOS)
* [ ] `homelab` deployment role, NGINX site and certificate
