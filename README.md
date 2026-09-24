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

## Dependencies

Agreed set, each added with the feature that needs it:

| Crate | Purpose |
|---|---|
| `tiny_http` | HTTP server |
| `ldap3` | LDAP bind and device entries |
| `p256`, `ecdsa`, `base64`, `serde_json` | Signing step-ca single-use tokens (ES256 JWS) |
| `hmac`, `sha2` | Session cookies and CSRF tokens |

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

## Status

* [x] Service skeleton, container image and CI
* [ ] LDAP sign-in restricted to `device-enrollers`
* [ ] Device registration in `ou=Devices`
* [ ] step-ca JWK provisioner and single-use token signing
* [ ] Windows enrolment script
* [ ] Linux enrolment script
* [ ] step-ca SCEP provisioner and challenge webhook
* [ ] iOS enrolment profile
* [ ] Expiry view for devices that renew manually (iOS)
* [ ] `homelab` deployment role, NGINX site and certificate
